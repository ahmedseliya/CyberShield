import axios from 'axios';

export default async (req, context) => {
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

        return new Response(JSON.stringify(response.data), {
            headers: { "Content-Type": "application/json" }
        });

    } catch (error) {
        return new Response(JSON.stringify({ error: "Failed to fetch data." }), {
            status: 500,
            headers: { "Content-Type": "application/json" }
        });
    }
};
