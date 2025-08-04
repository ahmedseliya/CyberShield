const axios = require('axios');

exports.handler = async function (event, context) {
    const VULNCHECK_API_KEY = process.env.VULNCHECK_API_KEY;

    // Always include these headers for CORS!
    const corsHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
    };

    // Handle browser "preflight" (OPTIONS) requests quickly
    if (event.httpMethod === 'OPTIONS') {
        return {
            statusCode: 200,
            headers: corsHeaders,
            body: 'OK'
        };
    }

    // Main logic for GET requests
    try {
        const response = await axios.get(
            "https://api.vulncheck.com/v3/index/nist-nvd2?size=100",
            {
                headers: {
                    "Authorization": `Bearer ${VULNCHECK_API_KEY}`
                }
            }
        );

        return {
            statusCode: 200,
            headers: corsHeaders,
            body: JSON.stringify(response.data)
        };

    } catch (error) {
        return {
            statusCode: error.response?.status || 500,
            headers: corsHeaders,
            body: JSON.stringify({ error: "Failed to fetch data from VulnCheck API." })
        };
    }
};
