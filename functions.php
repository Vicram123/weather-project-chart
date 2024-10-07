<?php
function create_user($con, $user_name, $password)
{
	// Check if the username already exists  
	$query = $con->prepare("SELECT * FROM users WHERE name = ? LIMIT 1");
	$query->bind_param("s", $user_name);
	$query->execute();
	$result = $query->get_result();

	if ($result && $result->num_rows > 0) {
		// Username already exists  
		return false;
	}

	// Hash the password before storing it  
	$hashed_password = password_hash($password, PASSWORD_DEFAULT);

	// Prepare an SQL statement to insert the new user  
	$insert_query = $con->prepare("INSERT INTO users (name, role, password, created_at) VALUES (?, 'user', ?, NOW())");
	$insert_query->bind_param("ss", $user_name, $hashed_password);

	// Execute and check if the user was created successfully  
	if ($insert_query->execute()) {
		// Write the new user data to the users.txt file  
		$user_data = "$user_name,$hashed_password,user," . date('Y-m-d H:i:s') . "\n";
		file_put_contents('users.txt', $user_data, FILE_APPEND);

		return true; // User created successfully  
	} else {
		return false; // Failed to create user  
	}
}
$user_data = file('users.txt');
foreach ($user_data as $line) {
	$user_info = explode(',', $line);
	$user_name = $user_info[0];
	$hashed_password = $user_info[1];
	$role = $user_info[2];
	$created_at = $user_info[3];
	// Do something with the user data  
}
function login_user($con, $user_name, $password)
{
	$query = $con->prepare("SELECT * FROM users WHERE name = ? LIMIT 1");
	$query->bind_param("s", $user_name);
	$query->execute();
	$result = $query->get_result();

	if ($result && $result->num_rows > 0) {
		$user = $result->fetch_assoc();
		// Verify the password
		if (password_verify($password, $user['password'])) {
			return $user; // Successful login
		}
	}
	return false; // Failed login
}

function check_login($con)
{
	// Ensure the session is started
	if (session_status() == PHP_SESSION_NONE) {
		session_start();
	}

	if (isset($_SESSION['user_id'])) {
		$id = $_SESSION['user_id'];

		// Use prepared statements to prevent SQL injection
		$query = $con->prepare("SELECT * FROM users WHERE id = ? LIMIT 1");
		$query->bind_param("i", $id);
		$query->execute();
		$result = $query->get_result();

		if ($result && $result->num_rows > 0) {
			return $result->fetch_assoc();
		}
	}

	// Redirect to login if user is not found or not logged in
	header("Location: login.php"); // Change to your login page
	die;
}

?>