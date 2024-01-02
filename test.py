from flask import Flask, render_template, redirect, url_for, request, flash
from flask_bootstrap import Bootstrap

app = Flask(__name__)
bootstrap = Bootstrap(app)


@app.route('/')
def test():
    return render_template('test.html')


if __name__ == '__main__':
    app.run()
