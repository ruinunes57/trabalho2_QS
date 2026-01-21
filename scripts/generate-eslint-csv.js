const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

console.log('Running ESLint...');

// Increase maxBuffer to 10MB to handle large JSON output
exec('npx eslint . --format json', { maxBuffer: 1024 * 1024 * 10 }, (error, stdout, stderr) => {
    if (stderr && !stdout) {
        console.error('ESLint Error:', stderr);
        return;
    }

    try {
        const results = JSON.parse(stdout);
        const rows = [];

        // CSV Header
        rows.push(['File', 'Line', 'Column', 'Severity', 'Rule ID', 'Message'].join(','));

        let totalErrors = 0;
        let totalWarnings = 0;

        results.forEach(result => {
            const filePath = path.relative(process.cwd(), result.filePath);

            result.messages.forEach(msg => {
                const severity = msg.severity === 2 ? 'Error' : 'Warning';
                if (msg.severity === 2) totalErrors++;
                else totalWarnings++;

                // Escape double quotes by doubling them, and wrap field in quotes
                const message = `"${msg.message.replace(/"/g, '""')}"`;
                const ruleId = msg.ruleId || 'N/A';

                rows.push([
                    `"${filePath}"`,
                    msg.line,
                    msg.column,
                    severity,
                    ruleId,
                    message
                ].join(','));
            });
        });

        const csvContent = rows.join('\n');
        const outputPath = path.join(process.cwd(), 'eslint-report.csv');

        fs.writeFileSync(outputPath, csvContent);

        console.log(`Successfully generated eslint-report.csv`);
        console.log(`Total: ${rows.length - 1} issues (${totalErrors} errors, ${totalWarnings} warnings)`);

    } catch (e) {
        console.error('Error parsing ESLint output:', e);
        if (stderr) console.error('Stderr:', stderr);
    }
});
