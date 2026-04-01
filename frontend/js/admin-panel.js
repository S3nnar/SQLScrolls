(function () {
    const output = document.getElementById("output");
    const errorBox = document.getElementById("error");

    function showError(message) {
        errorBox.textContent = message;
        errorBox.classList.remove("d-none");
    }

    function clearError() {
        errorBox.classList.add("d-none");
        errorBox.textContent = "";
    }

    function showOutput(data) {
        output.textContent = JSON.stringify(data, null, 2);
    }

    function parseJsonOrThrow(raw) {
        if (!raw || !raw.trim()) return {};
        return JSON.parse(raw);
    }

    function parseCsv(raw) {
        if (!raw) return [];
        return raw.split(",").map((item) => item.trim()).filter(Boolean);
    }

    async function guardAdminAccess() {
        API.loginExisting();
        if (API.loginStatus !== LoginStatus.LOGGED_IN) {
            window.location.href = "index.html";
            return false;
        }

        const isAdmin = await API.refreshAdminStatus();
        if (!isAdmin) {
            window.location.href = "index.html";
            return false;
        }

        return true;
    }

    async function run() {
        try {
            const allowed = await guardAdminAccess();
            if (!allowed) return;

            document.getElementById("load-summary").addEventListener("click", async () => {
                clearError();
                try {
                    showOutput(await API.adminGetSummary());
                } catch (err) {
                    showError(String(err));
                }
            });

            document.getElementById("load-recent").addEventListener("click", async () => {
                clearError();
                try {
                    showOutput(await API.adminGetRecentUsers(50));
                } catch (err) {
                    showError(String(err));
                }
            });

            document.getElementById("bulk-update").addEventListener("click", async () => {
                clearError();
                try {
                    const userIds = parseCsv(document.getElementById("bulk-user-ids").value);
                    const usernames = parseCsv(document.getElementById("bulk-usernames").value);
                    const update = parseJsonOrThrow(document.getElementById("bulk-update-json").value);
                    const applyToRelatedCollections = document.getElementById("bulk-related").checked;

                    showOutput(await API.adminBulkUpdateUsers({
                        userIds,
                        usernames,
                        update,
                        applyToRelatedCollections,
                    }));
                } catch (err) {
                    showError(String(err));
                }
            });

            document.getElementById("run-query").addEventListener("click", async () => {
                clearError();
                try {
                    const collection = document.getElementById("query-collection").value;
                    const action = document.getElementById("query-action").value;
                    const limit = Number(document.getElementById("query-limit").value);
                    const payload = parseJsonOrThrow(document.getElementById("query-json").value);

                    showOutput(await API.adminRunCustomQuery({
                        collection,
                        action,
                        limit,
                        ...payload,
                    }));
                } catch (err) {
                    showError(String(err));
                }
            });
        } catch (err) {
            showError(String(err));
        }
    }

    run();
})();
