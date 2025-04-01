<?php

// Define your data as an array
$data = array(
  "message" => "Hello from PHP!",
  "timestamp" => time(),
);

// Encode the data into JSON
$json = json_encode($data);

// Set CORS headers
header("Access-Control-Allow-Origin: *");
header("Content-Type: application/json; charset=utf-8");

// Output the JSON data
echo $json;

?>
