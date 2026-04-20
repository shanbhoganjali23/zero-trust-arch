from flask import Flask, render_template

app = Flask(__name__)

@app.route('/admin-panel')
def admin_home():
    return render_template('admin-app.html')

if __name__ == '__main__':
    app.run(port=5004, debug=True)