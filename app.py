


from flask import request, make_response, flash, render_template, redirect, Flask
from datetime import datetime, timedelta
import jwt
import json
import csv
import re

app = Flask(__name__)
app.secret_key = "mysecretkey"


@app.route('/')
def default():
	return "server running"


@app.route('/fms', methods = ["GET"])
def main_page():
	return render_template("fms.html")



@app.route('/fms/student/login', methods = ["GET", "POST"])
def student_login():
	if request.method == "GET":
		return render_template("studentLogin.html")
	
	else:
		
		form = request.form
		uid = form['uid']
		password = form['password']
		
		print(uid, password)
		data = getFileData('students')
		print(data)
		if(password == searchData(data, uid, 'password')):
			flash(f"Welcome {searchData(data, uid, 'name')}.", category = 'success')
			exp_time = datetime.now() + timedelta(minutes = 10)
			exp_time_epoch = exp_time.timestamp()

			payload = {'payload' : {'type' : 'student', 'id' : uid}, 'exp' : exp_time_epoch}
			token = jwt.encode(payload, "secret@123", algorithm = "HS256")

			response = make_response(render_template('medium.html', data = "student"))
			response.set_cookie('jwt', 'Bearer ' + token)
			
			return response
		
		else:
			flash("Email or password is wrong.", category = 'error')
			return redirect('/fms/student/login')
	            
			
@app.route('/fms/student/register', methods = ["GET"])
def student_register():
	return "please contact your hod"
		
@app.route('/fms/student/home', methods = ["GET"])
def student_home():
	if request.method == "GET":
		
		res = validateJWT(request.cookies.get('jwt'))
		
		if(res['status'] != 200):
			return redirect("/fms/student/login")
		uid = res['data']['id']
		data1 = getFileData('students')
		data = []
		data.append(uid)
		data.append(searchData(data1, uid, 'name'))
		data.append(searchData(data1, uid, 'sem'))
		data.append(searchData(data1, uid, 'branch'))
		
		
		subjects = []
		
		subs = searchData(data1, uid, 'subjects').split(',')
		techs = searchData(data1, uid, 'teachers').split(',')
		
		for i in range(len(subs)):
			
			fi = {}
			fi['subject'] = subs[i]
			fi['teacher'] = techs[i]
			subjects.append(fi)
		
		
						
		return render_template("studentHome.html", data = data, data1 = subjects)

	
	
@app.route('/fms/review', methods = ["GET"])
def review():
	return render_template("review.html")


@app.route('/fms/review2', methods = ["GET"])
def review2():
	return render_template("review2.html")


@app.route('/fms/student/review/<idi>', methods = ["GET", "POST"])
def give_review(idi):
	
	
	res = validateJWT(request.cookies.get('jwt'))
	
	
	
	
	if(res['status'] != 200):
			return redirect("/fms/student/login")
			
	
	uid = res['data']['id']
	data1 = getFileData('students')
	
	subs = searchData(data1, uid, 'subjects').split(',')
	techs = searchData(data1, uid, 'teachers').split(',')
	
	idi = int(idi)
	sub = subs[idi-1]
	teach = techs[idi - 1]
	
	data = [sub, teach]
	
	if(request.method == "GET"):
		return render_template("review3.html", data = data)
		
	
	
	form = request.form
	
	print(form['review'], form['rating'], form['teacherName'], uid)
	
	file = open("reviews.csv", 'a', newline="")
	writer = csv.writer(file)
	
	l = []
	f = open("num.txt", 'r')
	num = int(f.read())
	f.close()
	f = open("num.txt", 'w')
	f.write(str(num + 1))
	f.close()
	l.append(str(num))
	l.append(uid)
	l.append(form['teacherName'])
	l.append(form['rating'])
	l.append(form['review'])
	writer.writerow(l)
	file.close()
	flash("Review submittd successfully", category = 'success')
	
	return redirect("/fms/student/home")	







@app.route('/fms/staff/login', methods = ["GET", "POST"])
def staff_login():
	if request.method == "GET":
		return render_template("staffLogin.html")
	
	else:
		
		form = request.form
		uid = form['sid']
		password = form['password']
		
		print(uid, password)
		data = getFileData('teachers')
		print(data)
		if(password == searchData(data, uid, 'password')):
			flash(f"Welcome Prof.{searchData(data, uid, 'name')}.", category = 'success')
			exp_time = datetime.now() + timedelta(minutes = 10)
			exp_time_epoch = exp_time.timestamp()

			payload = {'payload' : {'type' : 'teacher', 'id' : uid}, 'exp' : exp_time_epoch}
			token = jwt.encode(payload, "secret@123", algorithm = "HS256")

			response = make_response(render_template('medium.html', data = "staff"))
			response.set_cookie('jwt', 'Bearer ' + token)
			
			return response
		
		else:
			flash("Email or password is wrong.", category = 'error')
			return redirect('/fms/staff/login')


@app.route('/fms/staff/register', methods = ["GET"])
def staff_register():
	return "please contact your hod"




@app.route('/fms/staff/home', methods = ["GET"])
def staff_home():
	if request.method == "GET":
		
		res = validateJWT(request.cookies.get('jwt'))
		
		if(res['status'] != 200):
			return redirect("/fms/staff/login")
		uid = res['data']['id']
		data1 = getFileData('teachers')
		data = []
		data.append(uid)
		data.append(searchData(data1, uid, 'name'))
		data.append(searchData(data1, uid, 'subjects'))
		
		
		# subjects = []
		
		# subs = searchData(data1, uid, 'subjects').split(',')
		# techs = searchData(data1, uid, 'teachers').split(',')
		
		# for i in range(len(subs)):
			
		# 	fi = {}
		# 	fi['subject'] = subs[i]
		# 	fi['teacher'] = techs[i]
		# 	subjects.append(fi)
		
		
						
		return render_template("staffHome.html", data = data)#, data1 = subjects)




def getFileData(name):
	file = open(f"{name}.csv", 'r')
	
	reader = csv.reader(file)
	
	l = list(reader)
	
	file.close()
	
	return l


def searchData(data, uid, colName):
	
	index = -1
	
	for i in range(len(data[0])):
		if(data[0][i] == colName):
			index = i
			break
	
	
	if(index == -1):
		print("no such col name")
		return None
	
	for i in data:
		if(i[0] == uid):
			return i[index]
		
	
	print("no uid found")
	return None
			



def validateJWT(token):
	if token is None:
	    return {'message' : "invalid", status : 401}

	try:
	    if re.match("^Bearer *([^ ]+) *$", token, flags=0):
	        token = token.split(" ")[1]
	        try:
	            tokendata = jwt.decode(token, "secret@123", algorithms="HS256")
	            return {"data" : tokendata['payload'], 'status' : 200}
	        except jwt.ExpiredSignatureError as e:
	            return {'message' : str(e), 'status' : 400}
	        except Exception as e:
	            return {'message' : str(e), 'status' : 401}
	        print(tokendata)

	    else:
	        return {'message' : "INVALID_TOKEN", 'status' : 401}

	except Exception as e:
	    return {'message' : str(e), 'status' : 401}

# @app.route('fms/studet/login', )












if __name__ == "__main__":
	app.run(port = 8001, debug = True)
	