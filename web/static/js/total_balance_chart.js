"use strict";

(function () {
    // Default to dark mode
    var isDarkStyle = true;

    // Example condition to check if dark mode should be overridden
    if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) {
        isDarkStyle = false;
    }

    var o, e, r, s, t, a, i, n;
    var l = isDarkStyle ? 
        (o = config.colors_dark.cardColor, 
         e = config.colors_dark.headingColor, 
         r = config.colors_dark.textWhite,
        //  r = config.colors_dark.textMuted,
         s = config.colors_dark.borderColor, 
         t = "dark", 
         a = "#4f51c0", 
         i = "#595cd9",
         n = "#8789ff", 
         "#c3c4ff") 
        : 
        (o = config.colors.cardColor, 
         e = config.colors.headingColor, 
         r = config.colors.textMuted,
         s = config.colors.borderColor, 
         t = "", 
         a = "#e1e2ff", 
         i = "#c3c4ff", 
         n = "#a5a7ff", 
         "#696cff");

    // Selecting the total balance chart element
    var d = document.querySelector("#totalBalanceChart");
    
    // Chart configuration
    var c = {
        series: [{ data: [137, 210, 160, 275, 205, 315] }],
        chart: { 
            height: 250, 
            parentHeightOffset: 0, 
            parentWidthOffset: 0, 
            type: "line", 
            dropShadow: { 
                enabled: !0, 
                top: 10, 
                left: 5, 
                blur: 3, 
                color: config.colors.warning, 
                opacity: .15 
            }, 
            toolbar: { show: !1 } 
        }, 
        dataLabels: { enabled: !1 }, 
        stroke: { width: 4, curve: "smooth" }, 
        legend: { show: !1 }, 
        colors: [config.colors.warning], 
        markers: { 
            size: 6, 
            colors: "transparent", 
            strokeColors: "transparent", 
            strokeWidth: 4, 
            discrete: [{ 
                fillColor: config.colors.white, 
                seriesIndex: 0, 
                dataPointIndex: 5, 
                strokeColor: config.colors.warning, 
                strokeWidth: 8, 
                size: 6, 
                radius: 8 
            }],
            hover: { size: 7 } 
        }, 
        grid: { 
            show: !1, 
            padding: { top: -10, left: 0, right: 0, bottom: 10 } 
        },
        xaxis: {
            categories: ["Jan", "Feb", "Mar", "Apr", "May", "Jun"], 
            axisBorder: { show: !1 }, 
            axisTicks: { show: !1 },
            labels: { show: !0, style: { fontSize: "13px", colors: "#ccc" } }
        }, 
        yaxis: { labels: { show: !1 } }
    };
    
    // Rendering the chart if the element exists
    if (d !== null) {
        new ApexCharts(d, c).render();
        new ApexCharts(document.querySelector("#totalBalanceChart_0"), c).render();
    }
})();
