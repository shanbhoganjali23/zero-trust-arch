from flask import Flask, render_template
app = Flask(__name__)
@app.route('/hr-app')
def hr_home():
    return render_template('/hr-app.html')

@app.route('/hr-app/employees')
def employees():
    return render_template('/hr-app-employees.html')

@app.route('/hr-app/leave')
def leave():
    return render_template('/hr-app-leave.html')

if __name__ == '__main__':
    app.run(debug=True)