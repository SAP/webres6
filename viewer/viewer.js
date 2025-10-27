/* viewer.js - JavaScript for the IPv6 Web Resource Checker viewer HTML page 
 *
 * SPDX-FileCopyrightText: 2025 SAP SE and IPv6 Web Resource Checker contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 */

function getAPIBase() {
  return document.querySelector('link[rel="x-webres6-api"]').getAttribute('href');
}

async function loadSrvConfig() {
  // Load available extensions from the server
  try {
    const resp = await fetch(getAPIBase() + '/serverconfig');
    if (resp.ok) {
      const srvconfig = await resp.json();
      // Server message
      if (srvconfig && srvconfig.message) {
        $('#srvmessage').html(srvconfig.message);
        $('#srvmessage').removeClass('template');
      }
      // Privacy policy
      if (srvconfig && srvconfig.privacy_policy) {
        $('#privacy-policy').html(srvconfig.privacy_policy);
      }
      // Max wait time
      if (srvconfig && srvconfig.max_wait) {
        $('#waitTime').attr('max', srvconfig.max_wait);
      }
      // Extension selector
      if (srvconfig && srvconfig.extensions && Array.isArray(srvconfig.extensions) && srvconfig.extensions.length > 0) {
        srvconfig.extensions.forEach(function(ext) {
          $('#extensionSelect').append(
            $('<option>').val(ext).text(ext)
          );
          $('#extensionSelectContainer').removeClass('template');
        });
      }
      // Screenshot selector
      if (srvconfig && srvconfig.screenshot_modes && Array.isArray(srvconfig.screenshot_modes) && srvconfig.screenshot_modes.length > 0) {
        srvconfig.screenshot_modes.forEach(function(mode) {
          $('#screenshotSelect').append(
            $('<option>').val(mode).text(mode.charAt(0).toUpperCase() + mode.slice(1))
          );
        });
        $('#screenshotSelectContainer').removeClass('template');
      } 
      // Whois switch
      if (srvconfig && srvconfig.whois) {
        $('#whoisSwitchContainer').removeClass('template');
      }
      // Show input section
      $('#input').removeClass('template');
    }
  } catch (e) {
    // ignore errors
  }
}

function createResultsDomContainer(url) {
  const domContainerId = Date.now();
  const domContainer = $('#results-template').clone();
  const overview = domContainer.find('.overview');
  domContainer.attr('id', domContainerId);
  overview.children().remove();
  domContainer.find('.url').text(url);
  domContainer.removeClass('template');
  domContainer.insertAfter('#input');
  return [domContainer, overview, domContainerId];
}

function handleJsonDrop(event) {
  $.each(event.dataTransfer.files, function(i, file) {
    if (file.type === 'application/json') {
      const reader = new FileReader();
      reader.onload = function(e) {
        const data = e.target.result;
        let jsonData;
        try {
          jsonData = JSON.parse(data);
        } catch (e) {
          alert('Invalid JSON data dropped. Please drop a valid JSON object.');
        }
        const [domContainer, overview, domContainerId] = createResultsDomContainer('Dropped URL');
        renderData(jsonData, domContainer, overview);
      };
      reader.readAsText(file);
    } else {
      alert('Please drop a valid JSON file.');
    }
  });
}

async function analyzeURL(url, wait, screenshot = 'none',  ext = null, whois = 'false') {
  // Generate new container
  const [domContainer, overview, domContainerId] = createResultsDomContainer(url);
  $('#results-template .overview .status.status-loading').clone().appendTo(overview);
  // Load the JSON data from the server
  let apiUrl = getAPIBase() + `/url(${encodeURIComponent(url)})?wait=${wait}&screenshot=${screenshot}&whois=${whois}`;
  if (ext && ext !== "(none)") apiUrl += `&ext=${encodeURIComponent(ext)}`;
  const response = await fetch(apiUrl);
  domContainer.find('.overview .status.status-loading').remove();
  if (response.ok) {
    const data = await response.json();
    renderData(data, domContainer, overview);
  } else {
    const errStatus = $('#results-template .overview .status.error').clone()
    errStatus.find('.placeholder').text(response.statusText);
    overview.append(errStatus);
  }
}

function renderData(data, domContainer, overview) {
  // Status
  if (data.error) {
    const errStatus = $('#results-template .overview .status.error').clone()
    errStatus.find('.placeholder').text(data.error);
    overview.append(errStatus);
  }
  let v6status;
  if (data.ipv6_only_ready == true) {
    v6status = $('#results-template .overview .status.ipv6only-ready').clone()
  } else if (data.ipv6_only_ready === false) {
    v6status = $('#results-template .overview .status.ipv6only-not-ready').clone()
  } else {
    v6status = $('#results-template .overview .status.ipv6only-unknown').clone()
  }
  overview.append(v6status);
  // Timestamp
  if (data.ts) {
    const date = new Date(data.ts);
    domContainer.find('.timestamp').html(date.toLocaleString('en-UK', { timeZoneName: 'short', hour12: false }));
  }
  // URL
  if(data.url) {
    domContainer.find('.url').html(data.url);
  }
  // Hosts
  if (data.hosts && Object.keys(data.hosts).length > 0) {
    const hosts= domContainer.find('.hosts');
    const hostsTable = hosts.find('.hosts_table');
    let hasWhoisInfo = false;
    const sortedHosts = Object.keys(data.hosts).sort(function(a, b) {
      if(data.hosts[a].domain_part===data.hosts[b].domain_part){
        return data.hosts[a].local_part.localeCompare(data.hosts[b].local_part);
      } else {
        return data.hosts[a].domain_part.localeCompare(data.hosts[b].domain_part);
      }});
    $.each(sortedHosts, function(idx, hostname) {
      // prepare host stuff
      const info = data.hosts[hostname];
      const ips = info.ips ? Object.keys(info.ips).sort() : [];
      const hostsTableBlock = $('<tbody>').addClass('host-block');
      const hostsTableBlockHead = $(`<td rowspan=1 class="hostname host-localpart">${info.local_part}</td><td rowspan=1 class="hostname host-dompart">${info.domain_part}</td>`);
      let row = $('<tr>').append(hostsTableBlockHead);
      let numRows = 1;
      function appendRow() {
        hostsTableBlockHead.attr('rowspan', numRows);
        hostsTableBlock.append(row);
        row = $('<tr>');
        numRows++;
      }
      // render IP addresses as rows or print note if none found
      if (ips.length === 0) {
        row.append('<td colspan=2/><td>No IPs</td>');
        appendRow();
      }
      $.each(ips, function(i, ip) {
        // prepare to render protocols as sub-rows
        let pr = info.ips[ip].transport.map(function(v, n, a) {
          return `<td class="protocol">${v.length>0?v[0]:'_'}</td>`+
                  `<td class="protocol">${v.length>1?v[1]:'_'}</td>`
        });
        // pre-format whois info if available
        let asn = ''
        let ipnetname = '';
        let asdescr = '';
        if (info.ips[ip].whois) {
          hasWhoisInfo = true;
          asn = info.ips[ip].whois.asn || '';
          asdescr = info.ips[ip].whois.asn_description || '';
          ipnetname = info.ips[ip].whois.network.name || '';
        }
        // first row with ip
        row.append(pr[0]); pr.shift();
        row.append(`<td rowspan="${pr.length + 1}" class="as-number" title='${asdescr}'>${asn}</td>`);
        row.append(`<td rowspan="${pr.length + 1}" class="as-descr" title='${asn}'>${asdescr}</td>`);
        row.append(`<td rowspan="${pr.length + 1}" class="ip-address ${info.ips[ip].address_family.toLowerCase()}" title="${ipnetname}">${ip}</td>`);
        row.append(`<td rowspan="${pr.length + 1}" class="ip-netname ${info.ips[ip].address_family.toLowerCase()}" title="${ip}">${ipnetname}</td>`);
        appendRow();
        // additional rows for additional protocols
        $.each(pr, function(pi, pe) {
          row.append(pr[0]);
          appendRow();
        });
      })
      // render other per-host info
      const hostInfoDiv = $('<div>')
      row.addClass('host-info-block');
      row.addClass('hide');
      row.append($('<td colspan=6>').append(hostInfoDiv));
      if (info.urls && info.urls.length) {
        hostInfoDiv.append('<strong>URLs</strong>');
        let urlList =$('<ul class="urls">');
        $.each(info.urls, function(i, url) {
          urlList.append(`<li>${url}</li>`);
        });
        hostInfoDiv.append(urlList);
      }
      if (info.subject_alt_names && info.subject_alt_names.length) {
        hostInfoDiv.append('<strong>Subject Alt Names</strong>');
        const sanList = $('<ul class="subject-alts">');
        $.each(info.subject_alt_names, function(i, san) {
          sanList.append(`<li>${san}</li>`);
        });
        hostInfoDiv.append(sanList);
      }
      hostsTableBlock.find('td.hostname').on('click', function(e) {
        row.toggle();
      });
      hostsTableBlock.append(row);
      // add block to the table
      hostsTable.append(hostsTableBlock);
    });
    // Prepare whois info toggling
    const asNumberCells = hostsTable.find('.as-number');
    const asDescrCells = hostsTable.find('.as-descr');
    const ipAddressCells = hostsTable.find('.ip-address');
    const ipNetnameCells = hostsTable.find('.ip-netname');
    // Show/hide whois info based on availability and default
    asNumberCells.toggleClass('hide', !hasWhoisInfo);
    asDescrCells.addClass('hide');
    ipNetnameCells.addClass('hide');
    if (hasWhoisInfo) {
      // Toggle between as-number and as-descr on click
      asNumberCells.on('click', function(e) {
        asNumberCells.addClass('hide');
        asDescrCells.removeClass('hide');
      });
      asDescrCells.on('click', function(e) {
        asDescrCells.addClass('hide');
        asNumberCells.removeClass('hide');
      });
      // Toggle between ip-address and ip-netname on click
      ipAddressCells.on('click', function(e) {
        ipAddressCells.addClass('hide');
        ipNetnameCells.removeClass('hide');
      });
      ipNetnameCells.on('click', function(e) {
        ipNetnameCells.addClass('hide');
        ipAddressCells.removeClass('hide');
      });
    }
    // Show the hosts section
    hosts.removeClass('template');
  }
  if (data.screenshot) {
    const screenshot = domContainer.find('.screenshot');
    const img = screenshot.find('img');
    img.attr("src", `data:image/png;base64, ${data.screenshot}`);
    img.attr("alt", `Screenshot of ${data.URL}`);
    screenshot.removeClass('template');
  }
  const footer = domContainer.find('.contents-container-footer');
  if (data.timings) {
    const timingContainer = footer.find('.timings');
    timingContainer.find('.placeholder').text(
      $.map(['crawl', 'screenshot', 'extract', 'whois'], function(label) { return data.timings[label] ? `${label}: ${data.timings[label].toFixed(2)}s` : null; }).join(', ')
    );
    timingContainer.removeClass('template');
  }
  const rawdataContainer = footer.find('.rawdata');
  rawdataContainer.find('a').attr('href', `data:text/json;charset=utf-8;base64, ${btoa(JSON.stringify(data, null, 2))}`);
  rawdataContainer.removeClass('template');
}

$(document).ready(function() {
  // Load server config (extensions, screenshot modes, whois support)
  loadSrvConfig();
  // Check for URL anchor and analyze it if present
  const anchorUrl = document.URL.split('#')[1];
  if (anchorUrl) {
    $('#input').hide();
    analyzeURL(anchorUrl);
  }
  // Add form submit handler
  $('#urlForm').on('submit', function(e) {
    e.preventDefault();
    analyzeURL($('#urlInput').val(), parseFloat($('#waitTime').val()), $('#screenshotSelect').val(), $('#extensionSelect').val(), $('#whoisLookup').is(':checked'));
    $('#urlInput').val('');
  });
  // Drag and drop support
  document.body.ondragover = function(e) { e.preventDefault(); }
  document.body.ondrop = function(e) { e.preventDefault(); handleJsonDrop(e); };
});