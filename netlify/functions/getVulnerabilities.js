const axios = require('axios');

// The only change is on this next line
module.exports.handler = async function (event, context) {
    // This is your secret key, which Netlify will provide securely.
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
            body: JSON.stringify(response.data)
        };

    } catch (error) {
        return {
            statusCode: 500,
            body: JSON.stringify({ error: "Failed to fetch data." })
        };
    }
};
