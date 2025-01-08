from module_phishing import train_phishing_model

model, accuracy, report = train_phishing_model("input/phishing-csv/phishing_site_urls.csv")

print("Précision :", accuracy)
print(report)