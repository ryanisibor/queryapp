const fetch = require("node-fetch");
const querystring = require("querystring");

module.exports = async function (context, req) {
  const upn = req.query.upn;

  if (!upn) {
    context.res = {
      status: 400,
      body: { error: "Please provide a userPrincipalName (?upn=...)" }
    };
    return;
  }

  try {
    // 🔑 Get token for Graph
    const tenantId = process.env.TENANT_ID;
    const clientId = process.env.CLIENT_ID;
    const clientSecret = process.env.CLIENT_SECRET;

    const tokenResponse = await fetch(
      `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`,
      {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: querystring.stringify({
          client_id: clientId,
          scope: "https://graph.microsoft.com/.default",
          client_secret: clientSecret,
          grant_type: "client_credentials"
        })
      }
    );

    const tokenData = await tokenResponse.json();
    const token = tokenData.access_token;

    if (!token) {
      throw new Error("Failed to obtain Graph access token");
    }

    // 📡 Call Graph for authentication methods (v1.0)
    const methodsResponse = await fetch(
      `https://graph.microsoft.com/v1.0/users/${upn}/authentication/methods`,
      {
        headers: { Authorization: `Bearer ${token}` }
      }
    );
    const methodsData = await methodsResponse.json();

    if (methodsData.error) {
      throw new Error(
        `Graph error (methods): ${methodsData.error.code} - ${methodsData.error.message}`
      );
    }

    // 📡 Call Graph for sign-in preferences (beta)
    const prefResponse = await fetch(
      `https://graph.microsoft.com/beta/users/${upn}/authentication/signInPreferences`,
      {
        headers: { Authorization: `Bearer ${token}` }
      }
    );
    const prefData = await prefResponse.json();

    if (prefData.error) {
      throw new Error(
        `Graph error (preferences): ${prefData.error.code} - ${prefData.error.message}`
      );
    }

    const preferredDefault = prefData.userPreferredMethodForSecondaryAuthentication || "unknown";

    // 🎯 Normalize methods
    const methods = methodsData.value
      .map((m) => {
        const type = m["@odata.type"];

        // Skip passwordAuthenticationMethod (not MFA)
        if (type === "#microsoft.graph.passwordAuthenticationMethod") {
          return null;
        }

        let friendly = {};
        switch (type) {
          case "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod":
            friendly = {
              type: "Microsoft Authenticator",
              device: m.displayName || "Authenticator app",
              isDefault: (preferredDefault === "microsoftAuthenticator")
            };
            break;

          case "#microsoft.graph.phoneAuthenticationMethod":
            friendly = {
              type: "Phone",
              number: m.phoneNumber || "N/A",
              phoneType: m.phoneType,
              smsSignInEnabled: m.smsSignInState === "enabled",
              isDefault: (preferredDefault === "mobilePhone")
            };
            break;

          case "#microsoft.graph.fido2AuthenticationMethod":
            friendly = {
              type: "FIDO2 Security Key",
              model: m.model || "Security Key",
              isDefault: (preferredDefault === "fido2")
            };
            break;

          case "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod":
            friendly = {
              type: "Windows Hello for Business",
              device: m.displayName || "Windows Hello",
              keyStrength: m.keyStrength,
              isDefault: (preferredDefault === "windowsHelloForBusiness")
            };
            break;

          case "#microsoft.graph.softwareOathAuthenticationMethod":
            friendly = {
              type: "Software OATH Token",
              device: m.displayName || "OATH TOTP",
              isDefault: (preferredDefault === "softwareOath")
            };
            break;

          default:
            friendly = { type: type || "Unknown", raw: m, isDefault: false };
        }
        return friendly;
      })
      .filter((m) => m !== null);

    context.res = {
      status: 200,
      body: {
        upn: upn,
        preferredDefaultFromGraph: preferredDefault,
        methods: methods
      }
    };
  } catch (err) {
    context.log.error(err);
    context.res = {
      status: 500,
      body: { error: err.message }
    };
  }
};
