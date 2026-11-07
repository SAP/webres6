# S3 access via Workload Identity Federation (Gardener → AWS)

This describes how to give the webres6 API pod credential-free access to an S3
bucket on a Gardener-managed shoot cluster, replacing a static `awsSecret`
(IAM access key + secret) with short-lived tokens exchanged via OIDC.

The pod presents a projected Kubernetes service-account token to AWS STS
(`AssumeRoleWithWebIdentity`), which returns temporary credentials for an IAM
role. Trust is established by registering the shoot's **managed service account
issuer** as an OIDC identity provider in AWS IAM.

> **Which mechanism is this?** This uses the shoot's own service-account token
> issuer — tokens have subject `system:serviceaccount:<ns>:<sa>` and are minted
> by a projected volume we control in the pod spec. This is *not* the Gardener
> [`WorkloadIdentity`](https://gardener.cloud/docs/gardener/shoot/shoot-workload-identity/)
> /`CredentialsBinding` resource path (subjects `gardener.cloud:workloadidentity:…`),
> which federates credentials for *infrastructure provisioning*. The OIDC
> federation pattern is the same; see also the provider-aws
> [workload identity federation docs](https://gardener.cloud/docs/extensions/infrastructure-extensions/gardener-extension-provider-aws/usage/#aws-workload-identity-federation).

## Prerequisites

- `aws` CLI configured with permission to manage IAM (create OIDC providers,
  roles, policies) in the target account.
- `kubectl` access to the shoot cluster.
- An existing S3 bucket (here `webres6-test` in `eu-west-1`).
- The shoot exposes a public OIDC discovery endpoint for its service-account
  issuer. On the Gardener canary landscape this is already enabled; the issuer
  URL lives under `discovery.ingress.garden.<landscape>.k8s.ondemand.com`.

The commands below use these variables — fill in the placeholders for your
deployment:

```bash
export AWS_ACCOUNT=<your-aws-account-id>
export AWS_REGION=eu-west-1
export S3_BUCKET=webres6-test
export ROLE_NAME=webres6-api-s3-test
export AUDIENCE=sts.amazonaws.com                    # must match everywhere (chart default)
export K8S_NAMESPACE=test
export K8S_SA=test-webres6                            # chart fullname: <release>-webres6
```

## 1. Find the shoot's service-account issuer URL

Target the shoot cluster and extract issuer URL

```bash
gardenctl target --garden YOUR_LANDSCPE --project YOUR_PROJECT --shoot CLUSTER_NAME
export ISSUER_URL="$(kubectl get --raw /.well-known/openid-configuration | jq -r .issuer)"
```

## 2. Register the issuer as an OIDC provider in AWS IAM

`--client-id-list` is the **audience** — the single most error-prone value; it
must match the token's `aud` claim and the role trust policy exactly. The issuer
uses a publicly trusted certificate, so IAM fetches and pins the thumbprint
automatically — no `--thumbprint-list` needed.

```bash
aws iam create-open-id-connect-provider \
  --url "$ISSUER_URL" \
  --client-id-list "$AUDIENCE"
```

The provider ARN is the issuer URL with `https://` stripped:

```bash
export OIDC_ARN="arn:aws:iam::${AWS_ACCOUNT}:oidc-provider/${ISSUER_URL#https://}"
```

## 3. Create the IAM role with a web-identity trust policy

The trust policy allows `AssumeRoleWithWebIdentity` only for tokens from this
issuer whose `aud` matches the audience and whose `sub` is the API's Kubernetes
service account (`system:serviceaccount:<namespace>:<serviceaccount>`):

```bash
cat > trust-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Principal": { "Federated": "${OIDC_ARN}" },
      "Condition": {
        "StringEquals": {
          "${ISSUER_URL#https://}:aud": "${AUDIENCE}",
          "${ISSUER_URL#https://}:sub": "system:serviceaccount:${K8S_NAMESPACE}:${K8S_SA}"
        }
      }
    }
  ]
}
EOF

aws iam create-role \
  --role-name "$ROLE_NAME" \
  --assume-role-policy-document file://trust-policy.json
```

## 4. Attach the S3 access policy

The API only writes and reads report objects, so it needs just `s3:PutObject`
and `s3:GetObject` on the bucket contents:

```bash
cat > s3-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:PutObject", "s3:GetObject"],
      "Resource": "arn:aws:s3:::${S3_BUCKET}/*"
    },
    {
      "Effect": "Allow",
      "Action": [ "s3:ListBucket" ],
      "Resource": "arn:aws:s3:::${S3_BUCKET}"
    }
  ]
}
EOF

aws iam put-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-name webres6-s3-access \
  --policy-document file://s3-policy.json
```

> **Report expiry:** the API does not delete objects. Configure report
> retention as an S3 **lifecycle/expiration rule on the bucket** (e.g. expire
> objects after N days) rather than granting the role `s3:DeleteObject`.

## 5. Configure the Helm values

Set the following in your deployment values file (e.g.
`deploy/<fqdn>.values.yaml`). `api.awsRoleARN` is the single source of truth: the
chart generates the `eks.amazonaws.com/role-arn` ServiceAccount annotation from
it *and* injects the web-identity env vars + a projected token volume into the
API pod. Leave `api.awsSecret` unset.

```yaml
api:
  s3Bucket: "webres6-test"
  s3Endpoint: "https://s3.dualstack.eu-west-1.amazonaws.com"
  awsRegion: "eu-west-1"                                       # required: no IMDS on IPv6-only shoots
  awsRoleARN: "arn:aws:iam::<your-aws-account-id>:role/webres6-api-s3-test"
  serviceAccount:
    create: true
    # tokenAudience defaults to sts.amazonaws.com; set it only if you
    # registered a different audience in step 2.
```

Notes:

- `awsRegion` must be set explicitly. IPv6-only shoots cannot reach the IMDS
  endpoint boto3 would otherwise use for region discovery.
- `tokenAudience` defaults to `sts.amazonaws.com`. Override it only if the OIDC
  provider in step 2 was registered with a different audience string.
- The ServiceAccount name defaults to the chart fullname (`<release>-webres6`),
  which must match the `sub` in the trust policy from step 3.

## 6. Deploy and verify

```bash
helm upgrade --install test ../helm -n "$K8S_NAMESPACE" \
  -f deploy/<fqdn>.values.yaml 
```

Confirm the pod received the web-identity wiring:

```bash
POD=$(kubectl get pod -n "$K8S_NAMESPACE" -l app=webres6-api -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n "$K8S_NAMESPACE" "$POD" -- env | grep AWS_
# expect: AWS_REGION, AWS_ROLE_ARN, AWS_WEB_IDENTITY_TOKEN_FILE=/var/run/secrets/sts-token/token
```

A successful crawl that archives to S3 confirms the full chain. Watch the API
logs for any `archiving result … to S3` errors.

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `Token audience contains more than one audience while authorized party is not present` | The pod used the *default* SA token (multiple audiences). | Use a projected token with a single audience — the chart does this via the `sts-token` volume when `awsRoleARN` is set. |
| `The web identity token provided could not be validated` | Token `aud` (or issuer) doesn't match the OIDC provider registration. | Make `tokenAudience`, the provider `--client-id-list`, and the trust-policy `:aud` identical. Verify the issued token with the command below. |
| `AccessDenied … not authorized to perform: s3:PutObject` | Role assumed successfully, but its policy doesn't allow the action/resource. | Check the resource ARN in step 4 — object actions need `arn:aws:s3:::<bucket>/*`. |

Inspect the token the pod will present (decode the `aud`, `iss`, `sub` claims):

```bash
kubectl create token "$K8S_SA" -n "$K8S_NAMESPACE" --audience "$AUDIENCE" \
  | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool
```

`iss` must equal the provider URL from step 1, `aud` must contain `$AUDIENCE`,
and `sub` must be `system:serviceaccount:$K8S_NAMESPACE:$K8S_SA`.
