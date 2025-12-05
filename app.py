from flask import Flask, jsonify,render_template
from services import get_vulns,get_bounty
app = Flask(__name__)

def cve_search():
    vulns = get_vulns()
    results = get_bounty(vulns)
    return render_template('index.html', insert_something=results)
@app.route("/")
def welcome():
    return cve_search()

if __name__ == "__main__":
    app.run(debug=True)