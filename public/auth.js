const AxisAuth = (() => {
  const tokenKey = "axis_access_token";
  const userKey = "axis_user";
  const token = () => sessionStorage.getItem(tokenKey);
  const nativeFetch = window.fetch.bind(window);
  window.fetch = (input, init={}) => {
    const url = typeof input === "string" ? input : input.url;
    if (url && url.startsWith(window.AXIS_CONFIG.apiBase) && token()) {
      const headers = new Headers(init.headers || (input instanceof Request ? input.headers : undefined));
      headers.set("Authorization", "Bearer " + token());
      init = {...init, headers};
    }
    return nativeFetch(input, init);
  };
  const user = () => { try { return JSON.parse(sessionStorage.getItem(userKey) || "null"); } catch { return null; } };
  async function request(path, options={}) {
    const headers = new Headers(options.headers || {});
    if (token()) headers.set("Authorization", "Bearer " + token());
    const response = await fetch(window.AXIS_CONFIG.apiBase + path, {...options, headers});
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      if (response.status === 401) logout();
      throw new Error(data.detail || "The request could not be completed.");
    }
    return data;
  }
  function save(data) {
    sessionStorage.setItem(tokenKey, data.access_token);
    sessionStorage.setItem(userKey, JSON.stringify(data.user));
  }
  function logout() {
    sessionStorage.removeItem(tokenKey); sessionStorage.removeItem(userKey);
    location.href = "index.html";
  }
  async function guard(role) {
    if (!token()) { location.href = "index.html"; return; }
    try {
      const me = await request("/auth/me");
      if (role && me.role !== role) { location.href = me.role === "admin" ? "admin-dashboard.html" : "client-overview.html"; return; }
      sessionStorage.setItem(userKey, JSON.stringify(me));
      document.querySelectorAll("[data-axis-company]").forEach(el => el.textContent = me.company_name || "Axis Solutions");
      document.querySelectorAll("[data-axis-user]").forEach(el => el.textContent = me.name || me.email);
    } catch { logout(); }
  }
  return {request, save, logout, guard, user, token};
})();
