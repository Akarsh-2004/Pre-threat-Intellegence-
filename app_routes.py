from flask import render_template, request, jsonify, redirect, url_for
import joblib
import os
import logic.email_check as email_check
import logic.phishing_check as phishing_check
import logic.whois_check as whois_check
from logic import ip_checker


#----------------------------------------------------------------------------------------------------------------------------------------


def setup_routes(app):
    @app.route('/')
    def home():
        return render_template('index.html')


#check Email----------------------------------------------------------------------------------------------------------------------------------------

    @app.route('/check_email', methods=['POST'])
    def check_email():
        email = request.form.get('email')
        if not email:
            return redirect(url_for("home"))

        result, phishing = email_check.analyze_email(email)
        status = "❌ Phishing Detected" if phishing else "✅ Safe Email"
        result = {
            "email id": email,
            "status": status
        }
        return render_template('results.html', result=result)

#check url----------------------------------------------------------------------------------------------------------------------------------------

    @app.route('/check_url', methods=['POST'])
    def check_url():
        url = request.form.get('url')
        if not url:
            return redirect(url_for('home'))

        reputation, suspicious = phishing_check.check_url(url)
        
        # Determine if it's phishing or not
        phishing = suspicious  # This will be True if suspicious

        result = {
            "URL Given": url,
            "Reputation": reputation,
            "Suspicion": "⚠️ HIGHLY Suspicious!" if phishing else "✅ Safe"
        }

        return render_template('results.html', result=result, phishing=phishing)

#check who is----------------------------------------------------------------------------------------------------------------------------------------

    @app.route('/check_whois', methods=['POST'])
    def check_whois():
        domain = request.form.get('domain')
        if not domain:
            return redirect(url_for('home'))

        creation_date, expiration_date, registrar = whois_check.get_whois_info(domain)
        result = {
            "Creation Date": str(creation_date), 
            "Expiration Date": str(expiration_date), 
            "Registrar": registrar
        }
        return render_template('results.html', result=result)

#check ip----------------------------------------------------------------------------------------------------------------------------------------


    @app.route('/ip_check', methods=['POST'])
    def ip_check():
        ipToCheck = request.form.get('ip_add')
        if not ipToCheck:
            return redirect(url_for('home'))

        # Fetch analysis results
        status, location, ISP, dns_records = ip_checker.check_ip(ipToCheck)

        result = {
            "IP": ipToCheck,
            "Status": status,
            "Location": location,
            "ISP": ISP,
            "DNS Records": dns_records
        }

        return render_template('results.html', result=result)




    
