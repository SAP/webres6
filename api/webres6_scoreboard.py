class Scoreboard:
    def __init__(self, storage_manager):
        self.storage_manager = storage_manager

    def enter(self, report):
        """ Enter a new report into the scoreboard.
            If the scoreboard exceeds max_entries, remove the oldest entry.
        """

        if report.get('error', None) is not None:
            return  # do not enter errored reports

        scorecard = {
            'report_id': report.get('ID', None),
            'ts': report.get('ts', None),
            'url': report.get('url', None),
            'domain': report.get('domain', None),
            'ipv6_only_score': report.get('ipv6_only_score', 0),
            'ipv6_only_dns_score': report.get('ipv6_only_dns_score', 0),
            'ipv6_only_http_score': report.get('ipv6_only_http_score', 0),
            'ipv6_only_ready': report.get('ipv6_only_ready', False),
        }

        return self.storage_manager.put_scorecard(scorecard)

    def get_entries(self, max_entries=23):
        """ Return the current scoreboard entries.
        """
        return self.storage_manager.get_scorecards(max_entries=max_entries)
