# Vulnerability report of app.py
These are the vulnerabilities found when the python code was tested.
***

<br>
<br>
<br>
<br>


## SQL injection

In the routes `/login` (line **60**) and `/user` (line **116**) the queries for the databases are made with f-strings without any escape or securization of any kind. Therefore an attacker can manipulate the parameters (`username`, `password`, or `name`) to execute arbitrary SQL commands. This can lead to bypass authentication, modifying data or leaking sensitive data. <br>

 <img src="https://raw.githubusercontent.com/sdeiturralde/App-analysis/refs/heads/main/imgs/1.png"/>

<br>
<br>
<br>


## Path traversal

In both routes `/download` (line **94**) and `/upload` (line **105**) exist the risk of path traversal since both take the parameter join whatever it is written on the parameter with the default path allowing an attacker to escape it and get sensitive information. <br>
An example could be "http://localhost:5000/download?file=../../../../etc/passwd"

<br>
<br>
<br>

## Reflected Cross-Site Scripting (XSS)

In the route `/search` on the lines **86** and **87** the query is not sanitized. It is directly injected in the html code allowing an attacker to inject malicious JavaScript code.
<br>

<img src="https://raw.githubusercontent.com/sdeiturralde/App-analysis/refs/heads/main/imgs/3.png"/>
<img src="https://raw.githubusercontent.com/sdeiturralde/App-analysis/refs/heads/main/imgs/4.png"/>

<br>
<br>
<br>

## Missing authentication

There's a lack of verification in many endpoints like `/users` making their information fulla accessible to anyone without any credentials. <br>

<img src="https://raw.githubusercontent.com/sdeiturralde/App-analysis/refs/heads/main/imgs/2.png"/>

<br>
<br>
<br>

## Hardcoded secrets

In the lines **18** and **19** there are hardcoded an API key and a secret token that should never be in the code. Anyone with source code access can obtain these secrets.

<br>
<br>
<br>

## Debug Mode enabled

In production it is very useful having these mode enabled but when you release it it is a must deactivating it. The pin code was awarded in the terminal and with that code you can force an exception and enter in the console allowing arbitrary code execution that can lead to a reverse shell. <br>

<img src="https://raw.githubusercontent.com/sdeiturralde/App-analysis/refs/heads/main/imgs/5.png"/>
<img src="https://raw.githubusercontent.com/sdeiturralde/App-analysis/refs/heads/main/imgs/6.png"/>
<img src="https://raw.githubusercontent.com/sdeiturralde/App-analysis/refs/heads/main/imgs/7.png"/>

<br>
<br>
<br>

## Lack of file upload restrictions

There are basically no rules that force or reject certain type of files allowing an attacker to upload large files to cause a disruption in the service or malicious PHP scripts.
