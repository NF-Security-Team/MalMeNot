using System;
using System.Data.SqlClient;
using System.IO;
using System.Security.Cryptography;

namespace MalMeNOT
{
    class SQLinsert
    {
        public static string FileMD5(string filename)
        {
            using (var md5 = MD5.Create())
            {
                using (var stream = File.OpenRead(filename))
                {
                    var hash = md5.ComputeHash(stream);
                    return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                }
            }
        }
        public static string FileSHA256(string filename)
        {
            using (var sha256 = SHA256.Create())
            {
                using (var stream = File.OpenRead(filename))
                {
                    var hash = sha256.ComputeHash(stream);
                    return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                }
            }
        }
        public static string FileSHA512(string filename)
        {
            using (var sha512 = SHA512.Create())
            {
                using (var stream = File.OpenRead(filename))
                {
                    var hash = sha512.ComputeHash(stream);
                    return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                }
            }
        }



        //Metodi in Pausa in quanto bisogna comprare un server MySql
        public static void SQLFileInsert(string filepath)
        {
            
         
            //TODO
            FileInfo File = new FileInfo(filepath);
            //

            string conn_string = string.Format(@"Data Source =XXXXXXXX,PORT; Network Library =DBMSSOCN; Initial Catalog =Malwares; User ID =USER; Password =PASS;");
            SqlConnection con = new SqlConnection(conn_string);
                         
            
            con.Open();
            SqlCommand comm = con.CreateCommand();
            comm.CommandText = "INSERT INTO FilesAutomation(FileName,Path,Date_insert,MD5,SHA256,SHA512,Size,Type,Checked) VALUES(@FileName,@Path,@Date_insert,@MD5,@SHA256,@SHA512,@Size,@Type,@Checked)";
            comm.Parameters.AddWithValue("@FileName", File.Name);
            comm.Parameters.AddWithValue("@Path", File.FullName);
            comm.Parameters.AddWithValue("@Date_insert", DateTime.Now.ToString("dd/MM/yyyy"));
            comm.Parameters.AddWithValue("@MD5", FileMD5(filepath));
            comm.Parameters.AddWithValue("@SHA256", FileSHA256(filepath));
            comm.Parameters.AddWithValue("@SHA512", FileSHA512(filepath));
            comm.Parameters.AddWithValue("@Size", File.Length);
            comm.Parameters.AddWithValue("@Type", File.Extension);
            comm.Parameters.AddWithValue("@Checked", "null");
            comm.ExecuteNonQuery();
            con.Close();
        }

        public static void MySQLFileInsert(string filepath)
        {
            /*
            
            //TODO
            FileInfo File = new FileInfo(filepath);
            //
            string server = "XXX.XXX.XXX.XXX";
            string database = "Malwares";
            string uid = "USER";
            string password = "PASS";
            string connectionString;
            connectionString = "SERVER=" + server + ";" + "DATABASE=" +
            database + ";" + "UID=" + uid + ";" + "PASSWORD=" + password + ";" ;

            MySqlConnection conn = new MySqlConnection(connectionString);
            conn.Open();
            MySqlCommand comm = conn.CreateCommand();
            comm.CommandText = "INSERT INTO FilesAutomation(FileName,Path,Date_insert,MD5,SHA256,SHA512,Size,Type,Checked) VALUES(@FileName,@Path,@Date_insert,@MD5,@SHA256,@SHA512,@Size,@Type,@Checked)";
            comm.Parameters.AddWithValue("@FileName", File.Name);
            comm.Parameters.AddWithValue("@Path", File.FullName);
            comm.Parameters.AddWithValue("@Date_insert", DateTime.Now.ToString("dd/MM/yyyy"));
            comm.Parameters.AddWithValue("@MD5", FileMD5(filepath));
            comm.Parameters.AddWithValue("@SHA256", FileSHA256(filepath));
            comm.Parameters.AddWithValue("@SHA512", FileSHA512(filepath));
            comm.Parameters.AddWithValue("@Size", File.Length);
            comm.Parameters.AddWithValue("@Type", File.Extension);
            comm.Parameters.AddWithValue("@Checked", "null");
            comm.ExecuteNonQuery();
            conn.Close();
            */
        }

    }
}
