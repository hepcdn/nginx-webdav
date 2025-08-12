class WebDAVApp {
  constructor() {
    this.userManager = null;
    this.init();
  }

  async init() {
    try {
      // Fetch app configuration from server
      const config = await this.fetchAppConfig();

      // Configure OIDC client with fetched config
      this.userManager = new oidc.UserManager({
        authority: "https://cms-auth.cern.ch",
        client_id: config.public_client_id,
        redirect_uri: window.location.origin + window.location.pathname,
        scope: "openid profile storage.read:/ hepcdn.view",
        response_type: "code",
        post_logout_redirect_uri:
          window.location.origin + window.location.pathname,
        automaticSilentRenew: true,
        silent_redirect_uri: window.location.origin + window.location.pathname,
        loadUserInfo: true, // Explicitly request user info endpoint
      });

      this.bindEvents();
      this.setupOidcEvents();
      this.checkAuthStatus();
    } catch (error) {
      console.error("Failed to initialize:", error);
      this.showError("Failed to initialize: " + error.message);
    }
  }

  async fetchAppConfig() {
    try {
      const response = await fetch("/appconfig", {
        headers: {
          Accept: "application/json",
        },
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error("Error fetching app config:", error);
      throw new Error("Unable to fetch application configuration");
    }
  }

  bindEvents() {
    document
      .getElementById("login-btn")
      .addEventListener("click", () => this.initiateLogin());
    document
      .getElementById("logout-btn")
      .addEventListener("click", () => this.logout());
    document
      .getElementById("refresh-gossip")
      .addEventListener("click", () => this.loadGossipData());
  }

  setupOidcEvents() {
    // Handle user loaded event
    this.userManager.events.addUserLoaded((user) => {
      console.log("User loaded:", user);
      this.showDashboard();
      this.loadGossipData();
    });

    // Handle user unloaded event
    this.userManager.events.addUserUnloaded(() => {
      console.log("User unloaded");
      this.showLogin();
    });

    // Handle access token expiring
    this.userManager.events.addAccessTokenExpiring(() => {
      console.log("Access token expiring");
    });

    // Handle access token expired
    this.userManager.events.addAccessTokenExpired(() => {
      console.log("Access token expired");
      this.logout();
    });

    // Handle silent renew error
    this.userManager.events.addSilentRenewError((error) => {
      console.error("Silent renew error:", error);
    });
  }

  async checkAuthStatus() {
    try {
      // Check if we're returning from OAuth callback
      if (
        window.location.search.includes("code=") ||
        window.location.search.includes("error=")
      ) {
        this.showLoading();
        await this.userManager.signinRedirectCallback();
        // Clean up URL
        window.history.replaceState(
          {},
          document.title,
          window.location.pathname
        );
        return;
      }

      // Check if we have a valid user session
      const user = await this.userManager.getUser();
      if (user && !user.expired) {
        this.showDashboard();
        await this.loadGossipData();
      } else {
        this.showLogin();
      }
    } catch (error) {
      console.error("Auth status check error:", error);
      this.showError("Authentication check failed: " + error.message);
      this.showLogin();
    }
  }

  setUserInfo(user) {
    // Try multiple fallback options for user display name
    let displayName = "Unknown User";

    if (user.profile) {
      displayName = user.profile.preferred_username || "User";
    } else if (user.access_token) {
      // If no profile, try to extract from token (basic fallback)
      displayName = "Authenticated User";
    }

    document.getElementById(
      "user-name"
    ).textContent = `Logged in as: ${displayName}`;
  }

  async initiateLogin() {
    try {
      await this.userManager.signinRedirect();
    } catch (error) {
      console.error("Login initiation error:", error);
      this.showError("Login failed: " + error.message);
    }
  }

  async loadGossipData() {
    try {
      const user = await this.userManager.getUser();
      if (!user || user.expired) {
        this.showLogin();
        return;
      }

      this.setGossipStatus("Loading gossip data...", "loading");

      const response = await fetch("/gossip", {
        headers: {
          Authorization: `Bearer ${user.access_token}`,
          Accept: "application/json",
        },
      });

      if (!response.ok) {
        if (response.status === 401) {
          // Token expired or invalid
          await this.logout();
          return;
        }
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();
      this.displayGossipData(data);
      this.setGossipStatus("Data loaded successfully", "success");
    } catch (error) {
      console.error("Error loading gossip data:", error);
      this.setGossipStatus("Error loading data: " + error.message, "error");
    }
  }

  displayGossipData(data) {
    const container = document.getElementById("gossip-data");
    container.innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
  }

  setGossipStatus(message, type) {
    const statusEl = document.getElementById("gossip-status");
    statusEl.textContent = message;
    statusEl.className = `status ${type}`;
  }

  async logout() {
    try {
      await this.userManager.signoutRedirect();
    } catch (error) {
      console.error("Logout error:", error);
      // Fallback: clear local session and show login
      await this.userManager.removeUser();
      this.showLogin();
    }
  }

  showLogin() {
    this.hideAllSections();
    document.getElementById("login-section").classList.remove("hidden");
  }

  async showDashboard() {
    this.hideAllSections();
    document.getElementById("dashboard-section").classList.remove("hidden");

    // Set user info whenever dashboard is shown
    try {
      const user = await this.userManager.getUser();
      if (user) {
        this.setUserInfo(user);
      }
    } catch (error) {
      console.error("Error getting user info for dashboard:", error);
    }
  }

  showLoading() {
    this.hideAllSections();
    document.getElementById("loading-section").classList.remove("hidden");
  }

  hideAllSections() {
    document.querySelectorAll(".section").forEach((section) => {
      section.classList.add("hidden");
    });
  }

  showError(message) {
    alert("Error: " + message); // In production, use a better error display
  }
}

// Initialize the app
document.addEventListener("DOMContentLoaded", () => {
  new WebDAVApp();
});
