from flask import Flask, render_template
app = Flask(__name__)
@app.route('/dev-app')
def dev_home():
    return render_template('/dev-app.html')

@app.route('/dev-app/repos')
def repos():
    return render_template('/dev-app-repos.html')

@app.route('/dev-app/builds')
def builds():
    return render_template('/dev-app-builds.html')

if __name__ == '__main__':
    app.run(debug=True)