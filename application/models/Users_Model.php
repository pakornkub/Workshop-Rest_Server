<?php defined('BASEPATH') OR exit('No direct script access allowed');

class Users_Model extends CI_Model {

    protected $users_table = 'users';

    /**
     * Use Registration
     * @param : {array} User Data
     */
    public function insert_user($data = array()){

        $this->db->insert($this->users_table,$data);

        return $this->db->insert_id();

    }

     /**
     * Use Login
     * @param : {array} User Data
     */
    public function user_login($data = array()){

        $sql = "
            select * from users where (username = ? or email = ?) and password = ?
        ";

        $query = $this->db->query($sql, array($data['username'], $data['username'], md5($data['password'])));

        if($query->num_rows() > 0)
        {
            return $query->result_array();
        }

        return FALSE;

    }

    public function fetch_all_users(){

        $sql = "
            select * from users
        ";

        $query = $this->db->query($sql);

        return $query->result_array();
       
    }


}