<!DOCTYPE html PUBLIC "-//IETF//DTD HTML 2.0//EN">
<HTML>
   <HEAD>

   	  <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css">
         <script src="https://ajax.aspnetcdn.com/ajax/jQuery/jquery-3.2.1.min.js"></script>
<script src="https://ajax.aspnetcdn.com/ajax/jQuery/jquery-3.2.1.min.js"></script>
<script src='https://code.jquery.com/jquery-3.1.0.min.js'></script>
<link href="style.css" type="text/css" rel="stylesheet">

      <TITLE>
         Safeer Mian Portfolio
      </TITLE>

   </HEAD>
<BODY>
<?php
echo("hahahahah"); 
print("Hallo Welt");
$hostname="jdbc:oracle:thin:@localhost:1521:xe";
$username="system";
$password="admin";
$dbname="library";
$usertable="test";
$yourfield = "name";
 
//Connect to the database
$connection = mysql_connect($hostname, $username, $password);
mysql_select_db($dbname, $connection);
echo("hahahahah");
//Setup our query
$query = "SELECT * FROM $usertable";
 
//Run the Query
$result = mysql_query($query);
 
//If the query returned results, loop through
// each result
if($result)
{
  while($row = mysql_fetch_array($result))
  {
    $name = $row["$yourfield"];
    echo "Name: " . $name; 

  }
}
 
?>
</BODY>
</HTML>
