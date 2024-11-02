from flask import Flask, render_template, request, jsonify
import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin

app = Flask(__name__)

def check_xss(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        xss_vulnerabilities = []
        for form in forms:
            inputs = form.find_all('input')
            for input_field in inputs:
                if input_field.get('type') in ['text', 'search', 'url', 'tel']:
                    xss_vulnerabilities.append(f"Potential XSS vulnerability in form: {form.get('action', '')}")
        
        return xss_vulnerabilities
    except:
        return ["Error checking for XSS vulnerabilities"]

def check_sql_injection(url):
    try:
        response = requests.get(url + "'")
        if "SQL syntax" in response.text or "mysql_fetch_array()" in response.text:
            return ["Potential SQL Injection vulnerability detected"]
        return []
    except:
        return ["Error checking for SQL Injection vulnerabilities"]

def check_open_redirects(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        links = soup.find_all('a')
        
        open_redirects = []
        for link in links:
            href = link.get('href')
            if href and ('redirect' in href or 'url' in href):
                open_redirects.append(f"Potential Open Redirect vulnerability: {urljoin(url, href)}")
        
        return open_redirects
    except:
        return ["Error checking for Open Redirect vulnerabilities"]

def check_misconfiguration(url):
    try:
        response = requests.get(url + "/robots.txt")
        if response.status_code == 200:
            return ["Potentially sensitive information in robots.txt"]
        return []
    except:
        return ["Error checking for misconfigurations"]

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form['url']
    
    vulnerabilities = {
        'XSS': check_xss(url),
        'SQL Injection': check_sql_injection(url),
        'Open Redirects': check_open_redirects(url),
        'Misconfigurations': check_misconfiguration(url)
    }
    
    return jsonify(vulnerabilities)

if __name__ == '__main__':
    app.run(debug=True)