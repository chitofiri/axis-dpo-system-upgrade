window.AXIS_CONFIG = (() => {
 const local = location.hostname === "localhost" || location.hostname === "127.0.0.1";
 const origin = local ? "http://localhost:8000" : "https://axis-dpo-api.onrender.com";
 return Object.freeze({apiBase:origin+"/api/v1",clientApiBase:origin+"/api/v1/client",adminApiBase:origin+"/api/v1/admin",clientOrigin:origin,adminOrigin:origin});
})();
