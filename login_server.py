from flask import Flask, send_file

app = Flask(__name__)

@app.route("/")
def login():
    return send_file("login.html")

if __name__ == "__main__":
    app.run(port=5050, debug=True)
