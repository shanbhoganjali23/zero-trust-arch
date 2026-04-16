from flask import Flask, render_template
app = Flask(__name__)
@app.route('/dev-app')
def dev_home():
    return render_template('/dev-app.html')

@app.route('/dev-app/proj')
def proj():
    return render_template('/dev-app-proj.html')

@app.route('/dev-app/buildStatuses')
def build_statuses():
    return render_template('/dev-app-buildStatuses.html')

if __name__ == '__main__':
    app.run(debug=True)