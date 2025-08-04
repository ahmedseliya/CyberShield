const axios = require('axios');

module.exports.handler = async function (event, context) {
    const VULNCHECK_API_KEY = process.env.VULNCHECK_API_KEY;

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
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(response.data)
        };

    } catch (error) {
        return {
            statusCode: 500,
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ error: "Failed to fetch data from VulnCheck API." })
        };
    }
};
