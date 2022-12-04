from selenium import webdriver
import time


driver = webdriver.Chrome("/local-ssd/.home/bpopovic/.cache/selenium/chromedriver/linux64/97.0.4692.71/chromedriver")
driver.get("https://www.google.com")

time.sleep(5)


driver.quit()
