/* viewer.js - JavaScript for the IPv6 Web Resource Checker viewer HTML page 
 *
 * SPDX-FileCopyrightText: 2025 SAP SE and IPv6 Web Resource Checker contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 */

function getAPIBase() {
  return document.querySelector('link[rel="x-webres6-api"]').getAttribute('href');
}

const timeFormatOptions = { timeZoneName: 'short', hour12: false , month: '2-digit', day: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit'};
/* Load server config
 * this loads and renders messages, browser extensions in remote Selenium, screenshot modes, whois support and more
 */
var srvSupportsArchiveLinks = false;
var srvSupportsScoreboard = false;
async function loadSrvConfig() {
  // load config
  try {
    const resp = await fetch(getAPIBase() + '/serverconfig');
    if (resp.ok) {
      const srvconfig = await resp.json();
      // render server message (if available)
      if (srvconfig && srvconfig.message) {
        $('#srvmessage').html(srvconfig.message);
        $('#srvmessage').removeClass('template');
      }
      // render privacy policy (if available)
      if (srvconfig && srvconfig.privacy_policy) {
        $('#privacy-policy').html(srvconfig.privacy_policy);
      }
      // update wait time control
      if (srvconfig && srvconfig.max_wait) {
        $('#waitTime').attr('max', srvconfig.max_wait);
      }
      // If browser extensions are available in remote selenium, show selector
      if (srvconfig && srvconfig.extensions && Array.isArray(srvconfig.extensions) && srvconfig.extensions.length > 0) {
        srvconfig.extensions.forEach(function(ext) {
          $('#extensionSelect').append(
            $('<option>').val(ext).text(ext)
          );
        });
        $('#extensionSelectContainer').removeClass('template');
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
      // Scoreboard switch
      if (srvconfig && srvconfig.scoreboard) {
        $('#scoreboardSwitchContainer').removeClass('template');
        $('#scoreboard').attr('checked', 'true');
      }
      // Whois switch
      if (srvconfig && srvconfig.whois) {
        $('#whoisSwitchContainer').removeClass('template');
        $('#whoisLookup').attr('checked', 'true');
      }
      // Archive link support
      if (srvconfig && srvconfig.archive) {
        srvSupportsArchiveLinks = true;
      }
      // Scoreboard support
      if (srvconfig && srvconfig.scoreboard) {
        srvSupportsScoreboard = true;
      }
     return true;
    }
  } catch (e) {
    console.error('Failed to load server config:', e);
  }
  return false;
}

/* Helper function to create new results container */
function createResultsDomContainer(url) {
  const domContainerId = Date.now();
  const domContainer = $('#results-template').clone();
  const overview = domContainer.find('.overview');
  domContainer.attr('id', domContainerId);
  overview.children().remove();
  domContainer.find('.url').text(url);
  domContainer.removeClass('template');
  domContainer.insertAfter('#results-template');
  return [domContainer, overview, domContainerId];
}

/* Render JSON dump of IPv6 Web Resource Checker dump */
function renderData(data, domContainer, overview, apiBase=getAPIBase()) {
  // Timestamp
  if (data.ts) {
    const date = new Date(data.ts);
    domContainer.find('.timestamp').html(date.toLocaleString('en-UK', timeFormatOptions));
  }
  // URL
  if(data.url) {
    domContainer.find('.url').html(data.url);
  }
  // set report anchor link
  if (data.ID) {
    domContainer.attr('id', `report:${data.ID}`);
  }
  // Error (if present)
  if (data.error) {
    const errStatus = $('#results-template .overview .status.error').clone();
    errStatus.find('.placeholder').text(data.error);
    overview.append(errStatus);
  }
  // Status
  let v6status;
  if (data.ipv6_only_ready === true) {
    v6status = $('#results-template .overview .status.ipv6only-ready').clone();
  } else if (data.ipv6_only_ready === false) {
    v6status = $('#results-template .overview .status.ipv6only-not-ready').clone();
  } else {
    v6status = $('#results-template .overview .status.ipv6only-unknown').clone();
  }
  overview.append(v6status);
  // IPv6-Only HTTP Score
  if (data.ipv6_only_score !== null) {
    const scoreStatus = $('#results-template .overview .status.ipv6only-score').clone();
    scoreStatus.find('progress').attr('value', (data.ipv6_only_score));
    scoreStatus.find('.percentage').text(`${(data.ipv6_only_score * 100).toFixed(1)}%`);
    scoreStatus.on('click', function() {
      $('.hidden-score').toggleClass('hide');
    });
    overview.append(scoreStatus);
  }
  // IPv6-Only HTTP Score
  if (data.ipv6_only_http_score !== null) {
    const httpScoreStatus = $('#results-template .overview .status.ipv6only-http-score').clone();
    httpScoreStatus.find('progress').attr('value', (data.ipv6_only_http_score));
    httpScoreStatus.find('.percentage').text(`${(data.ipv6_only_http_score * 100).toFixed(1)}%`);
    overview.append(httpScoreStatus);
  }
  // IPv6-Only DNS Score
  if (data.ipv6_only_dns_score !== null) {
    const dnsScoreStatus = $('#results-template .overview .status.ipv6only-dns-score').clone();
    dnsScoreStatus.find('progress').attr('value', (data.ipv6_only_dns_score));
    dnsScoreStatus.find('.percentage').text(`${(data.ipv6_only_dns_score * 100).toFixed(1)}%`);
    overview.append(dnsScoreStatus);
  }
  // add screenshot if present
  if (data.screenshot) {
    const screenshot = domContainer.find('.screenshot');
    const img = screenshot.find('img');
    img.attr("src", `data:image/png;base64, ${data.screenshot}`);
    img.attr("alt", `Screenshot of ${data.URL}`);
    screenshot.removeClass('template');
  }
  // render hosts table
  renderHostsTable(data, domContainer.find('.hosts'));
  // set footer
  const footer = domContainer.find('.contents-container-footer');
  if (data.timings) {
    const timingContainer = footer.find('.timings');
    timingContainer.find('.placeholder').text(
      $.map(['crawl', 'screenshot', 'extract', 'dnsprobe', 'whois'], function(label) { return data.timings[label] ? `${label}: ${data.timings[label].toFixed(2)}s` : null; }).join(', ')
    );
    timingContainer.removeClass('template');
  }
  if (apiBase && srvSupportsArchiveLinks && data.ID) {
    const archivelinkContainer = footer.find('.archivelink');
    archivelinkContainer.find('a').attr('href', `#report:${data.ID}`);
    archivelinkContainer.removeClass('template');
  }
  const rawdataContainer = footer.find('.rawdata');
  if (apiBase && srvSupportsArchiveLinks && data.ID) {
    rawdataContainer.find('a').attr('href', `${getAPIBase()}/report/${data.ID}`);
  } else {
    rawdataContainer.find('a').attr('href', `data:text/json;charset=utf-8;base64, ${btoa(JSON.stringify(data, null, 2))}`);
  }
  rawdataContainer.removeClass('template');
}

/* Ugly helper to render hosts data */
function renderHostsTable(data, hostsContainer) {
  if (data.hosts && Object.keys(data.hosts).length > 0) {
    const hostsTable = hostsContainer.find('.hosts_table');
    let hasDNSInfo = false;
    let hasWhoisInfo = false;
    const sortedHosts = Object.keys(data.hosts).sort(function(a, b) {
      if(data.hosts[a].domain_part === data.hosts[b].domain_part){
        return data.hosts[a].local_part.localeCompare(data.hosts[b].local_part);
      } else {
        return data.hosts[a].domain_part.localeCompare(data.hosts[b].domain_part);
      }
    });
    $.each(sortedHosts, function(idx, hostname) {
      let row = $('<tr>');
      let numRows = 1;
      // prepare host stuff
      const info = data.hosts[hostname];
      const ips = info.ips ? Object.keys(info.ips).sort() : [];
      const hostsTableBlock = $('<tbody>').addClass('host-block');
      const hostCells = $(`<td rowspan=1 class="hostname host-localpart">${info.local_part}</td><td rowspan=1 class="hostname host-dompart">${info.domain_part}</td>`);
      row.append(hostCells);
      const dnsCell = $('<td rowspan=1 class="dns-status"></td>'); 
      row.append(dnsCell);
      const hostsTableBlockHead = row.find('td');
      // set DNS status
      if (info.dns && info.dns.ipv6_only_ready !== undefined) {
        hasDNSInfo = true;
        if (info.dns.ipv6_only_ready === true) {
          dnsCell.addClass('dns-status-ipv6-only-ready');
          dnsCell.text('✔');
          dnsCell.attr('title', 'Hostname can be resolved from an IPv6-only resolver');
        } else {
          dnsCell.addClass('dns-status-not-ipv6-only-ready');
          dnsCell.text('✘');
          dnsCell.attr('title', 'Hostname cannot be resolved from an IPv6-only resolver');
        }
      }
      // contruct rows for IPs
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
                  `<td class="protocol">${v.length>1?v[1]:'_'}</td>`;
        });
        // render IP and whois cells
        const asnCell       = $(`<td rowspan="${pr.length}" class="as-number" />`);
        const asDescrCell   = $(`<td rowspan="${pr.length}" class="as-descr" />`);
        const ipCell        = $(`<td rowspan="${pr.length}" class="ip-address ${info.ips[ip].address_family.toLowerCase()}" >${ip}</td>`);
        const ipNetnameCell = $(`<td rowspan="${pr.length}" class="ip-netname ${info.ips[ip].address_family.toLowerCase()}" />`);
        // add whois info if available
        if (info.ips[ip].whois) {
          hasWhoisInfo = true;
          // fill data
          asnCell.text(info.ips[ip].whois.asn || '');
          asnCell.attr('title', info.ips[ip].whois.asn || '');
          asDescrCell.text(info.ips[ip].whois.asn_description || '');
          asDescrCell.attr('title', info.ips[ip].whois.network.name || '');
          ipNetnameCell.text(info.ips[ip].whois.network.name || '');
          ipNetnameCell.attr('title', ip);
          ipCell.attr('title', info.ips[ip].whois.network.name || '');
          // add toggles
          asnCell.on('click', function(e) { asnCell.addClass('hide'); asDescrCell.removeClass('hide'); } );
          asDescrCell.on('click', function(e) { asDescrCell.addClass('hide'); asnCell.removeClass('hide'); } );
          ipCell.on('click', function(e) { ipCell.addClass('hide'); ipNetnameCell.removeClass('hide'); } );
          ipNetnameCell.on('click', function(e) { ipNetnameCell.addClass('hide'); ipCell.removeClass('hide'); } );
        }
        // construct first row
        row.append(pr[0]); pr.shift();
        row.append(asnCell);
        row.append(asDescrCell);
        row.append(ipCell);
        row.append(ipNetnameCell);
        appendRow();
        // costruct additional rows for additional protocols
        $.each(pr, function(pi, pe) {
          row.append(pr[0]);
          appendRow();
        });
      });
      // render appendix with other per-host info
      const hostInfoDiv = $('<div>');
      row.addClass('host-info-block');
      row.addClass('hide');
      row.append($('<td colspan=8>').append(hostInfoDiv));
      if (info.urls && info.urls.length) {
        hostInfoDiv.append('<strong>URLs</strong>');
        let urlList = $('<ul class="urls">');
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
    // Show/hide DNS info based on availability and default
    hostsTable.find('.dns-status').toggleClass('hide', !hasDNSInfo);
    // Show/hide whois info based on availability and default
    hostsTable.find('.as-number').toggleClass('hide', !hasWhoisInfo);
    hostsTable.find('.as-descr').addClass('hide');
    hostsTable.find('.ip-netname').addClass('hide');
    // Show the hosts section
    hostsContainer.removeClass('template');
  }
}

/* Call API and fetch analysis */ 
async function analyzeURL(url, wait = 2, scoreboard_entry = false, screenshot = 'none', ext = null, whois = 'true') {
  // Generate new container
  const [domContainer, overview, domContainerId] = createResultsDomContainer(url);
  const loadingStatus = $('#results-template .overview .status.status-loading').clone();
  loadingStatus.appendTo(overview);
  // Retry configuration for HTTP 202 responses
  const maxRetries = 5;
  const baseDelay = 10*1000; // 10 seconds base delay
  // Build API URL
  let apiUrl = getAPIBase() + `/url(${encodeURIComponent(url)})?wait=${wait}&scoreboard=${scoreboard_entry}&screenshot=${screenshot}&whois=${whois}`;
  if (ext && ext !== "(none)") apiUrl += `&ext=${encodeURIComponent(ext)}`;
  // Retry logic with exponential backoff
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const response = await fetch(apiUrl);
      if (response.status === 202) {
        // HTTP 202 Accepted - request is still processing
        if (attempt < maxRetries) {
          const delay = baseDelay * attempt
          console.log(`HTTP 202 received, retrying in ${delay}ms (attempt ${attempt + 1}/${maxRetries + 1})`);
          // Update loading message to show retry status
          loadingStatus.find('strong').append(` … ${attempt}`);
          // Wait before retrying
          await new Promise(resolve => setTimeout(resolve, delay));
          continue; // Retry the request
        } else {
          // Max retries reached
          console.error(`Max retries (${maxRetries}) reached for HTTP 202 responses`);
          domContainer.find('.overview .status.status-loading').remove();
          const errStatus = $('#results-template .overview .status.error').clone();
          errStatus.find('.placeholder').text(`Request timed out after ${maxRetries} retries. Server is still processing the request.`);
          errStatus.removeClass('template');
          overview.append(errStatus);
          return;
        }
      } else if (response.ok) {
        // Success - process the response
        domContainer.find('.overview .status.status-loading').remove();
        const data = await response.json();
        renderData(data, domContainer, overview);
        return; // Exit successfully
      } else {
        // Other HTTP error - don't retry
        domContainer.find('.overview .status.status-loading').remove();
        const errStatus = $('#results-template .overview .status.error').clone();
        errStatus.find('.placeholder').text(`${response.status} ${response.statusText}`);
        try {
          const errorData = await response.json();
          if (errorData.error) {
            errStatus.find('.placeholder').text(`${errorData.error}`);
          }
        } catch (e) {
          // ignore JSON parse errors
        }
        errStatus.removeClass('template');
        overview.append(errStatus);
        return;
      }
    } catch (error) {
      // Network or other fetch error
      console.error(`Fetch error on attempt ${attempt + 1}:`, error);
      if (attempt < maxRetries) {
        const delay = baseDelay * Math.pow(2, attempt);
        console.log(`Network error, retrying in ${delay}ms (attempt ${attempt + 1}/${maxRetries + 1})`);
        // Update loading message to show retry status
        loadingStatus.find('strong').text(`Network error, retrying in ${delay/1000}s... (attempt ${attempt + 1}/${maxRetries + 1})`);
        await new Promise(resolve => setTimeout(resolve, delay));
        continue; // Retry the request
      } else {
        // Max retries reached for network errors
        domContainer.find('.overview .status.status-loading').remove();
        const errStatus = $('#results-template .overview .status.error').clone();
        errStatus.find('.placeholder').text(`Network error after ${maxRetries} retries: ${error.message}`);
        overview.append(errStatus);
        return;
      }
    }
  }
}

/* Call API and fetch analysis report by report ID */
async function analyzeReport(report) {
  // Generate new container
  const [domContainer, overview, domContainerId] = createResultsDomContainer(report.substring(0, 25));
  const loadingStatus = $('#results-template .overview .status.status-loading').clone();
  loadingStatus.appendTo(overview);
  // Fetch report data
  reportUrl = getAPIBase() + `/report/${encodeURIComponent(report)}`;
  try {
    const response = await fetch(reportUrl);
    if (response.ok) {
      // Success - process the response
      domContainer.find('.overview .status.status-loading').remove();
      const data = await response.json();
      renderData(data, domContainer, overview);
    } else {
      // HTTP error
      domContainer.find('.overview .status.status-loading').remove();
      const errStatus = $('#results-template .overview .status.error').clone();
      errStatus.find('.placeholder').text(`${response.status} ${response.statusText}`);
      errStatus.removeClass('template');
      overview.append(errStatus);
    }
  } catch (error) {
      domContainer.find('.overview .status.status-loading').remove();
      const errStatus = $('#results-template .overview .status.error').clone();
      errStatus.find('.placeholder').text(`${response.status} ${response.statusText}`);
      errStatus.removeClass('template');
      overview.append(errStatus);
  }
}

/* Load and render scoreboard */
async function loadScoreboard(resultsLimit=12) {
  // Check if scoreboard is supported
  if (!srvSupportsScoreboard) {
    return;
  }
  // Fetch scoreboard data
  const scoreboardUrl = getAPIBase() + `/scoreboard?limit=${resultsLimit}`;
  try {
    const response = await fetch(scoreboardUrl);
    if (response.ok) {
      // parse data
      const data = await response.json();
      $.each(data, function(idx, entry) {
        entry.ts = new Date(entry.ts);
      });
      if (data.length > 0) {
        console.log('Scoreboard loaded with', data.length, 'entries');
        // Sort data by score (descending - highest scores first)
        data.sort(function(a, b) {
          var score = -compareScoreboardEntries(a, b, 'ipv6_only_score');
          if (score !== 0) return score;
          var score = compareScoreboardEntries(a, b, 'url');
          if (score !== 0) return score;
          var score = -compareScoreboardEntries(a, b, 'ts');
          if (score !== 0) return score;
          return 0;
        });
        // Render scoreboard
        renderScoreboard(data);
        // Add sorting functionality to table headers
        $('#scoreboard th.sortable').on('click', function() {
          const column = $(this).data('sort');
          const reverse = $(this).hasClass('sorted-ascending');
          $('#scoreboard th.sortable').removeClass('sorted-ascending sorted-descending');
          if (reverse) {
            $(this).addClass('sorted-descending');
          } else {
            $(this).addClass('sorted-ascending');
          }
          data.sort(function(a, b) {
            var score = compareScoreboardEntries(a, b, column);
            if (reverse) return -score;
            return score;
          });
          renderScoreboard(data);
        });
      } else {
        console.log('No scoreboard entries available');
      }
    } else {
      console.error('Failed to fetch scoreboard:', response.status, response.statusText);
    }
  } catch (error) {
    console.error('Error loading scoreboard:', error);
  }
}

/* Compare two scoreboard entries by given column */
function compareScoreboardEntries(a, b, column) {
    switch(column) {
        case 'ipv6_only_score':
            if (a.ipv6_only_score < b.ipv6_only_score) return -1;
            if (a.ipv6_only_score > b.ipv6_only_score) return 1;
            // fallthrough
        case 'url':
            if (a.url < b.url) return -1;
            if (a.url > b.url) return 1;
            // fallthrough
        case 'ts':
            if (a.ts < b.ts) return -1;
            if (a.ts > b.ts) return 1;
            // fallthrough
    }
    return 0;
}

/* Render scoreboard data into the DOM */
function renderScoreboard(data) {
  // prepare scoreboard container references
  const scoreboardContainer = $('#scoreboard');
  const scoreboardTableBody = scoreboardContainer.find('.scoreboard-table tbody');
  scoreboardTableBody.children('tr:not(.template)').remove();
  //render scoreboard entries
  $.each(data, function(idx, entry) {
    const row = scoreboardTableBody.find('tr.template').clone();
    row.removeClass('template');
    // Use ipv6_only_score instead of score
    const score = entry.ipv6_only_score;
    row.find('.scoreboard-ipv6only-score .percentage').text(`${(score * 100).toFixed(1)}%`);
    row.find('.scoreboard-ipv6only-score progress').attr('value', score);
    const resultLink = row.find('.scoreboard-target a');
    resultLink.attr('href', `#report:${entry.report_id}`);
    resultLink.text(entry.url);
    resultLink.attr('title', entry.url);
    resultLink.on('click', async function(e) { e.preventDefault(); await analyzeReport(entry.report_id); window.location.hash = `report:${entry.report_id}`; });
    row.find('.scoreboard-timestamp').text(new Date(entry.ts).toLocaleString('en-UK', timeFormatOptions));
    scoreboardTableBody.append(row);
  });
  scoreboardContainer.removeClass('template');
}

/* Allow to load saved json dumps of previous analysis by dropping them somewhere on the browser window */
function handleJsonDrop(event) {
  $.each(event.dataTransfer.files, function(i, file) {
    if (file.type === 'application/json') {
      const reader = new FileReader();
      reader.onload = function(e) {
        const data = e.target.result;
        let jsonData;
        try {
          jsonData = JSON.parse(data);
          const [domContainer, overview, domContainerId] = createResultsDomContainer('Dropped URL');
          renderData(jsonData, domContainer, overview, null);
        } catch (e) {
          alert('Invalid JSON data dropped. Only IPv6 Web Resource Checker JSON dumps can be rendered!');
        }
      };
      reader.readAsText(file);
    } else {
      alert('Only IPv6 Web Resource Checker JSON dumps can be rendered!');
    }
  });
}

/* Load server config and register callbacks */ 
$(document).ready( async function() {
  // Check for URL anchor and analyze it if present
  const anchor = document.URL.split('#')[1];
  if (anchor) {
    const [verb, target] = anchor.split(':');
    if (verb.toLowerCase() === 'url' && target) {
      $('#input').hide();
      analyzeURL(decodeURIComponent(target));
    } else if (verb.toLowerCase() === 'report' && target) {
      $('#input').hide();
      analyzeReport(target)
    } else if (verb.toLowerCase() === 'scoreboard') {
      if (await loadSrvConfig()) {
        loadScoreboard(parseInt(target) || 12);
      }
    }
  } else {
    // Load server config and enable features
    s = await loadSrvConfig();
    if (!s) { return; }
    // enable scoreboard
    loadScoreboard(12);
    // show input form and add handlers
    $('#input').removeClass('template');
    $('#urlForm').on('submit', function(e) {
      e.preventDefault();
      analyzeURL($('#urlInput').val(), parseFloat($('#waitTime').val()), $('#scoreboardSwitch').is(':checked'), $('#screenshotSelect').val(), $('#extensionSelect').val(), $('#whoisLookup').is(':checked'));
      $('#urlInput').val('');
      $('#scoreboard').addClass('hide');
    });
  }
  // Drag and drop support
  document.body.ondragover = function(e) { e.preventDefault(); }
  document.body.ondrop = function(e) { e.preventDefault(); handleJsonDrop(e); };
});