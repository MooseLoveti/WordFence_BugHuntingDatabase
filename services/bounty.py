def get_bounty(vulns):
    result = vulns
    permission = ["Admin+","Author+","Contributor+","Subscriber+","Unauthenticated",]
    vulnerability = [""] #Thank you CodeX
    return result

# TODO: Implement bounty simulator logic.
# Idea: ingest WordFence bounty rules (e.g., unauth SQLi with 1k installs = $X),
# compute bounty per vuln using active_installs/title, and add a `bounty` field
# to each entry in `result` for display in index.html.
