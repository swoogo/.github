/**
 * Generate PR comment using Claude API
 *
 * This script calls the Anthropic API to generate a formatted PR comment
 * based on Terraform validation results. Falls back to basic formatting
 * if the API call fails.
 */

const https = require('https');
const fs = require('fs');
const path = require('path');

module.exports = async ({ github, context, core }, results, validateResult, mergeResult, versionChanges = []) => {
  const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
  const MAX_COMMENT_LENGTH = 65000;

  // Load prompt template
  const promptTemplatePath = path.join(__dirname, '..', 'prompts', 'terraform-pr-comment.md');
  let promptTemplate = '';
  try {
    promptTemplate = fs.readFileSync(promptTemplatePath, 'utf8');
  } catch (e) {
    console.log('Warning: Could not load prompt template, using fallback');
  }

  // Prepare input data for Claude — filter sensitive infrastructure values
  const sanitizedResults = results.map(env => ({
    ...env,
    resource_changes: (env.resource_changes || []).map(rc => ({
      address: rc.address,
      type: rc.type,
      actions: rc.actions
      // Intentionally omit before/after to avoid sending sensitive infrastructure values
    })),
    tfsec_results: env.tfsec_results ? {
      results: (env.tfsec_results.results || []).map(r => ({
        severity: r.severity,
        rule_id: r.rule_id,
        description: r.description,
        resource: r.resource
      }))
    } : null
  }));

  const inputData = {
    results: sanitizedResults,
    validateResult: validateResult,
    mergeResult: mergeResult,
    versionChanges: versionChanges,
    prNumber: context.payload.pull_request?.number,
    commitSha: context.payload.pull_request?.head?.sha?.substring(0, 7),
    timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC'
  };

  // Try Claude API first
  if (ANTHROPIC_API_KEY) {
    try {
      const claudeResponse = await callClaudeAPI(ANTHROPIC_API_KEY, promptTemplate, inputData);
      if (claudeResponse) {
        let body = claudeResponse;
        if (body.length > MAX_COMMENT_LENGTH) {
          body = body.substring(0, MAX_COMMENT_LENGTH - 100) + '\n\n*Comment truncated for length.*\n';
        }
        core.setOutput('body', body);
        return body;
      }
    } catch (e) {
      console.log(`Claude API error: ${e.message}. Falling back to basic formatting.`);
    }
  } else {
    console.log('No ANTHROPIC_API_KEY provided, using fallback formatting.');
  }

  // Fallback: Generate basic comment without Claude
  const fallbackBody = generateFallbackComment(results, validateResult, mergeResult, versionChanges, context);
  core.setOutput('body', fallbackBody);
  return fallbackBody;
};

async function callClaudeAPI(apiKey, promptTemplate, inputData) {
  const prompt = `${promptTemplate}

---

## Input Data

\`\`\`json
${JSON.stringify(inputData, null, 2)}
\`\`\`

---

Generate the PR comment now. Output ONLY the markdown comment, nothing else.`;

  const requestBody = JSON.stringify({
    model: 'claude-sonnet-4-20250514',
    max_tokens: 8000,
    messages: [
      {
        role: 'user',
        content: prompt
      }
    ]
  });

  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'api.anthropic.com',
      port: 443,
      path: '/v1/messages',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
        'Content-Length': Buffer.byteLength(requestBody)
      },
      timeout: 60000
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        if (res.statusCode !== 200) {
          reject(new Error(`API returned ${res.statusCode}: ${data}`));
          return;
        }
        try {
          const response = JSON.parse(data);
          const text = response.content?.[0]?.text || '';
          resolve(text);
        } catch (e) {
          reject(new Error(`Failed to parse response: ${e.message}`));
        }
      });
    });

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timeout'));
    });

    req.write(requestBody);
    req.end();
  });
}

function generateFallbackComment(results, validateResult, mergeResult, versionChanges, context) {
  const allPassed = validateResult === 'success' && mergeResult === 'success';

  // Count changes
  let totalAdd = 0, totalChange = 0, totalRemove = 0;
  let totalSecurityFindings = 0;
  let criticalCount = 0, highCount = 0, mediumCount = 0;

  for (const ws of results) {
    for (const rc of (ws.resource_changes || [])) {
      if (rc.actions?.includes('create')) totalAdd++;
      else if (rc.actions?.includes('update')) totalChange++;
      else if (rc.actions?.includes('delete')) totalRemove++;
    }
    if (ws.tfsec_results?.results) {
      for (const finding of ws.tfsec_results.results) {
        totalSecurityFindings++;
        const sev = (finding.severity || '').toUpperCase();
        if (sev === 'CRITICAL') criticalCount++;
        else if (sev === 'HIGH') highCount++;
        else mediumCount++;
      }
    }
  }

  const totalChanges = totalAdd + totalChange + totalRemove;
  let body = '# \u{1F680} Terraform PR Status\n\n';

  // Summary
  body += '## Summary\n\n';
  if (allPassed && totalSecurityFindings > 0) {
    body += '> \u2705 **All Clear** \u2014 Validation passed with informational security findings (details below).\n\n';
  } else if (allPassed) {
    body += '> \u2705 **All Clear** \u2014 Every validation step passed. This PR is safe to merge.\n\n';
  } else if (mergeResult !== 'success') {
    body += '> \u26A0\uFE0F **Needs Attention** \u2014 The synthetic merge test detected drift. Rebase before merging.\n\n';
  } else {
    body += '> \u274C **Blocked** \u2014 Validation failed. See details below before merging.\n\n';
  }

  body += `We validated ${results.length} environment${results.length !== 1 ? 's' : ''} and found `;
  body += `${totalChanges} infrastructure change${totalChanges !== 1 ? 's' : ''} `;
  body += `(${totalAdd} added, ${totalChange} modified, ${totalRemove} removed). `;
  if (totalSecurityFindings > 0) {
    body += `The security scan surfaced ${totalSecurityFindings} findings \u2014 see the Security section for details. `;
  }
  if (mergeResult === 'success') {
    body += 'The structural fingerprint of resource changes matches between the PR plan and a simulated post-merge plan, so merging will produce the same plan \u2014 no surprises. ';
  } else {
    body += 'The structural fingerprint differs between the PR plan and a simulated post-merge plan \u2014 rebase on main before merging. ';
  }
  if (allPassed) {
    body += 'This PR is safe to merge. ';
  }
  body += 'When you merge, a post-merge plan runs automatically to confirm the merged state. Apply remains manual \u2014 no infrastructure changes happen until someone runs terraform apply.';
  body += '\n\n---\n\n';

  // Infrastructure Changes
  body += '## \u{1F3D7}\uFE0F Infrastructure Changes\n\n';
  body += `This PR touches ${results.length} environment${results.length !== 1 ? 's' : ''} with ${totalChanges} total change${totalChanges !== 1 ? 's' : ''}. `;
  body += 'Here\u2019s what\u2019s happening in each one.\n\n';

  for (const ws of results) {
    body += `### ${ws.workspace_name}\n\n`;
    const changes = ws.resource_changes || [];
    if (changes.length === 0) {
      body += 'No infrastructure changes \u2014 this environment\u2019s plan is clean.\n\n';
      continue;
    }

    const added = changes.filter(r => r.actions?.includes('create'));
    const modified = changes.filter(r => r.actions?.includes('update'));
    const removed = changes.filter(r => r.actions?.includes('delete'));

    if (added.length > 0) {
      body += `**\u2795 Added (${added.length})**\n`;
      for (const r of added) {
        body += `- \`${simplifyResourceName(r.address)}\`\n`;
      }
    }
    if (modified.length > 0) {
      body += `**\u270F\uFE0F Modified (${modified.length})**\n`;
      for (const r of modified) {
        body += `- \`${simplifyResourceName(r.address)}\`\n`;
      }
    }
    if (removed.length > 0) {
      body += `**\u{1F5D1}\uFE0F Removed (${removed.length})**\n`;
      for (const r of removed) {
        body += `- \`${simplifyResourceName(r.address)}\`\n`;
      }
    }
    body += '\n';
  }
  body += '---\n\n';

  // Version Changes (new section)
  if (versionChanges && versionChanges.length > 0) {
    body += '## \u{1F4E6} Version Changes\n\n';
    body += `This PR updates ${versionChanges.length} version${versionChanges.length !== 1 ? 's' : ''}.\n\n`;

    // Group by category
    const byCategory = {};
    for (const vc of versionChanges) {
      if (!byCategory[vc.category]) byCategory[vc.category] = [];
      byCategory[vc.category].push(vc);
    }

    const categoryLabels = {
      core: 'Core Tools',
      provider: 'Terraform Providers',
      'ci-tool': 'CI/CD Tools',
      'github-action': 'GitHub Actions'
    };

    const blastRadius = {
      core: 'Affects all Terraform operations across both environments. Major version changes may alter plan behavior.',
      provider: 'May change how resources are managed. Provider upgrades can introduce new resource attributes or deprecate existing ones.',
      'ci-tool': 'Affects CI pipeline only. No impact on infrastructure state.',
      'github-action': 'Affects CI pipeline only. No impact on infrastructure state.'
    };

    for (const [category, changes] of Object.entries(byCategory)) {
      body += `### ${categoryLabels[category] || category}\n\n`;
      body += '| Tool | From | To |\n';
      body += '|------|------|----|\n';
      for (const vc of changes) {
        body += `| ${vc.tool} | \`${vc.from}\` | \`${vc.to}\` |\n`;
      }
      body += `\n> ${blastRadius[category] || 'Review changelog for breaking changes.'}\n\n`;
    }

    body += '---\n\n';
  }

  // Security & Compliance
  body += '## \u{1F512} Security & Compliance\n\n';

  const hasOpaErrors = results.some(ws => ws.opa_status === 'error');
  const hasOpaFailures = results.some(ws => ws.opa_status === 'fail');
  body += '### OPA Policy Check\n\n';
  if (hasOpaErrors) {
    body += '\u26A0\uFE0F Policy evaluation failed to execute \u2014 check runner logs and verify OPA binary integrity.\n\n';
  } else if (hasOpaFailures) {
    body += '\u26A0\uFE0F Policy warnings found \u2014 review the policy results for details.\n\n';
  } else {
    body += '\u2705 All environments compliant \u2014 no policy violations detected.\n\n';
  }

  const hasSecurityErrors = results.some(ws => ws.security_status === 'error');
  body += '### TFSec Findings\n\n';
  if (hasSecurityErrors) {
    body += '\u26A0\uFE0F Security scan failed to execute \u2014 check runner logs and verify tfsec binary integrity.\n\n';
  } else if (totalSecurityFindings > 0) {
    body += `**${totalSecurityFindings} findings** (${criticalCount} critical, ${highCount} high, ${mediumCount} medium)\n\n`;

    // Group findings by category
    const findingsByCategory = {};
    for (const ws of results) {
      for (const f of (ws.tfsec_results?.results || [])) {
        const desc = f.description || 'Uncategorized';
        if (!findingsByCategory[desc]) {
          findingsByCategory[desc] = { severity: f.severity || 'MEDIUM', resources: [], ruleId: f.rule_id || '' };
        }
        if (f.resource) findingsByCategory[desc].resources.push(f.resource);
      }
    }

    body += '<details>\n';
    body += '<summary>\u{1F4CB} View categorized findings</summary>\n\n';
    for (const [desc, info] of Object.entries(findingsByCategory)) {
      body += `**${desc}** (${info.severity})\n`;
      if (info.ruleId) body += `- Rule: \`${info.ruleId}\`\n`;
      const uniqueResources = [...new Set(info.resources)];
      if (uniqueResources.length > 0) {
        body += `- Resources: ${uniqueResources.map(r => `\`${r}\``).join(', ')}\n`;
      }
      body += '\n';
    }
    body += '</details>\n\n';

    body += '> \u{1F4A1} **Assessment**: These findings should be reviewed to determine if they are pre-existing infrastructure patterns or newly introduced issues.\n\n';
  } else {
    body += '\u2705 Clean scan \u2014 no security issues detected.\n\n';
  }
  body += '---\n\n';

  body += 'Questions? Ask **@platform-team** in Slack\n\n';
  body += '<sub>Generated by Swoogy Terraform CI/CD</sub>\n';

  return body;
}

function simplifyResourceName(address) {
  if (!address) return 'Unknown Resource';

  let name = address
    .replace(/^module\./g, '')
    .replace(/\.this\[\d+\]/g, '')
    .replace(/\[\d+\]/g, '')
    .replace(/\["[^"]+"\]/g, '');

  const parts = name.split('.');
  const lastPart = parts[parts.length - 1] || parts[0];

  return lastPart
    .replace(/_/g, ' ')
    .replace(/-/g, ' ')
    .split(' ')
    .map(word => {
      const upper = word.toUpperCase();
      if (['IAM', 'ECS', 'RDS', 'SSM', 'WAF', 'OIDC', 'VPC', 'ALB', 'EC2', 'S3', 'KMS', 'SNS', 'SQS'].includes(upper)) {
        return upper;
      }
      return word.charAt(0).toUpperCase() + word.slice(1).toLowerCase();
    })
    .join(' ');
}
