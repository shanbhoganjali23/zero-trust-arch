from flask import Flask, render_template
app = Flask(__name__)
@app.route('/finance-app')
def finance_home():
    return render_template('/finance-app.html')

@app.route('/finance-app/budgets')
def budgets():
    return render_template('/finance-app-budgets.html')

@app.route('/finance-app/invoices')
def invoices():
    return render_template('/finance-app-invoices.html')

if __name__ == '__main__':
    app.run(port=5002, debug=True)