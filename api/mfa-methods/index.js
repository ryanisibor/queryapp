const fetch = require("node-fetch");
const querystring = require("querystring");

// Map Graph values to friendly names
function mapPreferredDefault(value) {
  switch (value) {
    case "microsoftAuthenticator":
      return "Microsoft Authenticator app";
    case "push":
      return "Microsoft Authenticator app (push notification)";
    case "fido2":
      return "FIDO2 Security Key";
    case "windowsHelloForBusiness":
      return "Windows Hello for Business";
    case "mobilePhone":
      return "Mobile phone (SMS)";
    case "alternateMobilePhone":
      return "Alternate mobile phone (SMS)";
    case "officePhone":
      return "Office phone (SMS)";
    case "voiceMobile":
      return "Mobile phone (voice call)";
    case "voiceAlternateMobile":
      return "Alternate mobile phone (voice call)";
    case "voiceOffice":
      return "Office phone (voice call)";
    case "softwareOath":
    case "oath":
      return "Software OATH Token";
    case "email":
      return "Email (not recommended for MFA)";
    case "unknown":
    case null:
      return "No default MFA method configured";
    default:
      return value; // fallback to raw string
  }
}

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

    // 📡 Call Graph for methods (v1.0) and preferences (beta) in parallel
    const [methodsResponse, prefResponse] = await Promise.all([
      fetch(`https://graph.microsoft.com/v1.0/users/${upn}/authentication/methods`, {
        headers: { Authorization: `Bearer ${token}` }
      }),
      fetch(`https://graph.microsoft.com/beta/users/${upn}/authentication/signInPreferences`, {
        headers: { Authorization: `Bearer ${token}` }
      })
    ]);

    const [methodsData, prefData] = await Promise.all([
      methodsResponse.json(),
      prefResponse.json()
    ]);

    // Handle Graph errors for methods
    if (methodsData.error) {
      const code = methodsData.error.code || "";
      const message = methodsData.error.message || "Unknown Graph error";

      if (code === "Request_ResourceNotFound") {
        context.res = { status: 404, body: { error: `User ${upn} not found` } };
        return;
      }

      context.res = { status: 400, body: { error: `Graph error: ${message}` } };
      return;
    }

    // Handle Graph errors for preferences
    if (prefData.error) {
      const code = prefData.error.code || "";
      const message = prefData.error.message || "Unknown Graph error";

      if (code === "Request_ResourceNotFound") {
        context.res = { status: 404, body: { error: `User ${upn} not found` } };
        return;
      }

      context.res = { status: 400, body: { error: `Graph error: ${message}` } };
      return;
    }

    const preferredDefaultRaw =
      prefData.userPreferredMethodForSecondaryAuthentication || "unknown";
    const preferredDefaultFriendly = mapPreferredDefault(preferredDefaultRaw);

    // 🎯 Normalize methods
    const methods = methodsData.value
      .map((m) => {
        const type = m["@odata.type"];

        // Skip password and email authentication methods (not MFA)
        if (
          type === "#microsoft.graph.passwordAuthenticationMethod" ||
          type === "#microsoft.graph.emailAuthenticationMethod"
        ) {
          context.log(`Skipping method ${type} for user ${upn}`);
          return null;
        }

        let friendly = {};
        switch (type) {
          case "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod":
            friendly = {
              type: "Microsoft Authenticator",
              device: m.displayName || "Authenticator app",
              isDefault:
                preferredDefaultRaw === "microsoftAuthenticator" ||
                preferredDefaultRaw === "push"
            };
            break;

          case "#microsoft.graph.phoneAuthenticationMethod":
            friendly = {
              type: "Phone",
              number: m.phoneNumber || "N/A",
              phoneType: m.phoneType,
              smsSignInEnabled: m.smsSignInState === "enabled",
              isDefault: [
                "mobilePhone",
                "alternateMobilePhone",
                "officePhone",
                "voiceMobile",
                "voiceAlternateMobile",
                "voiceOffice"
              ].includes(preferredDefaultRaw)
            };
            break;

          case "#microsoft.graph.fido2AuthenticationMethod":
            friendly = {
              type: "FIDO2 Security Key",
              model: m.model || "Security Key",
              isDefault: preferredDefaultRaw === "fido2"
            };
            break;

          case "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod":
            friendly = {
              type: "Windows Hello for Business",
              device: m.displayName || "Windows Hello",
              keyStrength: m.keyStrength,
              isDefault: preferredDefaultRaw === "windowsHelloForBusiness"
            };
            break;

          case "#microsoft.graph.softwareOathAuthenticationMethod":
            friendly = {
              type: "Software OATH Token",
              device: m.displayName || "OATH TOTP",
              isDefault:
                preferredDefaultRaw === "softwareOath" ||
                preferredDefaultRaw === "oath"
            };
            break;

          default:
            context.log(
              `Encountered unknown auth method type: ${type} for user ${upn}`
            );
            friendly = { type: type || "Unknown", raw: m, isDefault: false };
        }
        return friendly;
      })
      .filter((m) => m !== null);

    // 📋 Summary log
    context.log(
      `User ${upn} has ${methods.length} MFA methods. Preferred default (raw: ${preferredDefaultRaw}, friendly: ${preferredDefaultFriendly})`
    );

    context.res = {
      status: 200,
      body: {
        upn: upn,
        preferredDefaultFromGraph: {
          raw: preferredDefaultRaw,
          friendly: preferredDefaultFriendly
        },
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
