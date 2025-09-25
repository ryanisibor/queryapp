const fetch = require("node-fetch");
const qs = require("querystring");

module.exports = async function (context, req) {
  const upn = req.query.upn || (req.body && req.body.upn);
  if (!upn) {
    context.res = { status: 400, body: { error: "Missing UPN" } };
    return;
  }

  try {
    // Load secrets from environment
    const tenantId = process.env.TENANT_ID;
    const clientId = process.env.CLIENT_ID;
    const clientSecret = process.env.CLIENT_SECRET;

    // 1. Get an access token from Azure AD
    const tokenResponse = await fetch(`https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: qs.stringify({
        client_id: clientId,
        client_secret: clientSecret,
        scope: "https://graph.microsoft.com/.default",
        grant_type: "client_credentials"
      })
    });

    const tokenData = await tokenResponse.json();
    if (!tokenData.access_token) {
      throw new Error(`Token request failed: ${JSON.stringify(tokenData)}`);
    }

    // 2. Call Graph API for MFA methods
    const graphResponse = await fetch(`https://graph.microsoft.com/v1.0/users/${upn}/authentication/methods`, {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });

    const graphData = await graphResponse.json();

    // 3. Return result to front-end
    context.res = {
      headers: { "Content-Type": "application/json" },
      body: { methods: graphData.value || [] }
    };

  } catch (err) {
    context.log.error("Graph call failed", err);
    context.res = {
      status: 500,
      body: { error: err.message }
    };
  }
};
