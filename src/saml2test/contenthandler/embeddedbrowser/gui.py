from PyQt4.QtGui import QLineEdit, QWidget
from PyQt4.QtCore import QUrl

class UrlInput(QLineEdit):
	def __init__(self, browser):
		super(UrlInput, self).__init__()
		self.browser = browser
		# add event listener on "enter" pressed
		self.returnPressed.connect(self._return_pressed)

	def _return_pressed(self):
		url = QUrl(self.text())
		# load url into browser frame
		self.browser.load(url)
