document.addEventListener('DOMContentLoaded', function() {
    Chart.defaults.font.family = 'Tahoma, sans-serif';
    Chart.defaults.plugins.legend.position = 'bottom';

    const chartColors = [
        '#007bff', '#28a745', '#ffc107', '#dc3545', '#17a2b8', '#6c757d',
        '#6610f2', '#e83e8c', '#fd7e14', '#20c997', '#004085', '#7952b3'
    ];

    function updateNoDataMessage(chartId, show) {
        const noDataEl = document.getElementById(chartId + 'NoData');
        const canvasEl = document.getElementById(chartId);
        if (noDataEl) noDataEl.style.display = show ? 'block' : 'none';
        if (canvasEl) canvasEl.style.display = show ? 'none' : 'block';
    }

    fetch('/api/admin/chart-data')
        .then(response => {
            if (!response.ok) throw new Error(`Network response error: ${response.statusText}`);
            return response.json();
        })
        .then(apiData => {
            const charts = [{
                    id: 'incidentTypeChart',
                    type: 'doughnut',
                    dataKey: 'chart_type',
                    label: 'Incident Types',
                    options: {
                        plugins: {
                            legend: {
                                display: apiData.chart_type && apiData.chart_type.labels && apiData.chart_type.labels.length <= 8
                            }
                        }
                    },
                    // Specific dataset options for doughnut
                    datasetOptions: {
                        backgroundColor: chartColors,
                        hoverOffset: 4
                    }
                },
                {
                    id: 'monthlyReportsChart',
                    type: 'line',
                    dataKey: 'chart_monthly',
                    label: 'Reports per Month',
                    options: { scales: { y: { beginAtZero: true, ticks: { stepSize: 1 } } } },
                    datasetOptions: { borderColor: '#007bff', backgroundColor: 'rgba(0, 123, 255, 0.1)', tension: 0.1, fill: true }
                },
                {
                    id: 'dowReportsChart',
                    type: 'bar',
                    dataKey: 'chart_dow',
                    label: 'Reports by Day of Week',
                    options: { scales: { y: { beginAtZero: true, ticks: { stepSize: 1 } } } },
                    datasetOptions: { backgroundColor: chartColors.slice(0, 7) }
                },
                {
                    id: 'hourlyReportsChart',
                    type: 'bar',
                    dataKey: 'chart_hourly',
                    label: 'Reports by Hour (UTC)',
                    options: { scales: { y: { beginAtZero: true, ticks: { stepSize: 1 } } } },
                    datasetOptions: { backgroundColor: '#28a745' }
                }
            ];

            charts.forEach(chartConfig => {
                const chartData = apiData[chartConfig.dataKey];
                if (apiData.total_reports > 0 && chartData && chartData.labels && chartData.labels.length > 0) {
                    updateNoDataMessage(chartConfig.id, false);

                    // Prepare dataset with combined general and specific options
                    const dataset = {
                        label: chartConfig.label,
                        data: chartData.data,
                        ...chartConfig.datasetOptions // Apply the options defined in the charts array
                    };

                    new Chart(document.getElementById(chartConfig.id), {
                        type: chartConfig.type,
                        data: {
                            labels: chartData.labels,
                            datasets: [dataset] // Use the prepared dataset
                        },
                        options: { responsive: true, maintainAspectRatio: false, ...chartConfig.options }
                    });
                } else {
                    updateNoDataMessage(chartConfig.id, true);
                }
            });
        })
        .catch(error => {
            console.error('Failed to fetch admin chart data:', error);
            ['incidentTypeChart', 'monthlyReportsChart', 'dowReportsChart', 'hourlyReportsChart'].forEach(id => updateNoDataMessage(id, true));
        });
});