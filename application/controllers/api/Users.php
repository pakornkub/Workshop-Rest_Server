<?php defined('BASEPATH') OR exit('No direct script access allowed');

use Restserver\Libraries\REST_Controller;

require APPPATH . '/libraries/REST_Controller.php';
 
class Users extends REST_Controller {

    public function __construct(){

        parent::__construct();
        //Load Users Model
        $this->load->model('Users_Model');

    }

    /**  
     * User Register
     * ---------------------------------
     * @param: fullname
     * @param: email address
     * @param: password
     * @param: username
     * ---------------------------------
     * @method : POST 
     * @link : user/register
     */
    public function register_post(){

        header("Access-Controll-Allow-Origin: *");

        #XSS Filtering  (https://codeigniter.com/userguide3/libraries/security.html)
        $_POST = $this->security->xss_clean($_POST);

        #Form Validation (https://codeigniter.com/userguide3/libraries/form_validation.html)
        $this->form_validation->set_rules('full_name', 'Full Name', 'trim|required');
        $this->form_validation->set_rules('username', 'Username', 'trim|required|is_unique[users.username]|alpha_numeric|max_length[15]',
                array('is_unique' => 'This %s already exists please enter another username')
        );
        $this->form_validation->set_rules('email', 'Email', 'trim|required|is_unique[users.email]|valid_email|max_length[80]',
                array('is_unique' => 'This %s already exists please enter another email')
        );
        $this->form_validation->set_rules('password', 'Password', 'trim|required|max_length[100]');

        if ($this->form_validation->run() == FALSE)
        {
            //Form Validation Error
            $massage = array(
                'status'    => FALSE,
                'error'     => $this->form_validation->error_array(),
                'massage'   => validation_errors()
            );

            $this->response($massage, REST_Controller::HTTP_NOT_FOUND);
        }
        else
        {
            $insert_data = array(
                'username'      => $this->input->post('username',TRUE),
                'email'         => $this->input->post('email',TRUE),
                'password'      => md5($this->input->post('password',TRUE)),
                'full_name'     => $this->input->post('full_name',TRUE),
                'insert'        => time(),
                'update'        => time()
            );

            //Insert User in Database
            $output = $this->Users_Model->insert_user($insert_data);

            if($output > 0 && isset($output))
            {
                //Success 200 Code Send
                $massage = array(
                    'status'    => TRUE,
                    'massage'   => 'User Registration Successful'
                );

                $this->response($massage, REST_Controller::HTTP_OK);
            }
            else
            {
                //Error
                $massage = array(
                    'status'    => FALSE,
                    'massage'   => 'Not Register Your Account'
                );

                $this->response($massage, REST_Controller::HTTP_NOT_FOUND);
            }
        }
 
    }

     /**  
     * User Login API
     * ---------------------------------
     * @param: username or email
     * @param: password
     * ---------------------------------
     * @method : POST 
     * @link : user/login
     */
    public function login_post(){

        header("Access-Controll-Allow-Origin: *");

        #XSS Filtering  (https://codeigniter.com/userguide3/libraries/security.html)
        $_POST = $this->security->xss_clean($_POST);

        #Form Validation (https://codeigniter.com/userguide3/libraries/form_validation.html)
        $this->form_validation->set_rules('username', 'Username', 'trim|required');
        $this->form_validation->set_rules('password', 'Password', 'trim|required');

        if ($this->form_validation->run() == FALSE)
        {
            //Form Validation Error
            $massage = array(
                'status'    => FALSE,
                'error'     => $this->form_validation->error_array(),
                'massage'   => validation_errors()
            );

            $this->response($massage, REST_Controller::HTTP_NOT_FOUND);
        }
        else
        {
            $data_login = array(

                'username' => $this->input->post('username'),
                'password' => $this->input->post('password')
            );

            //Load Login Function
            $output = $this->Users_Model->user_login($data_login);

            if(isset($output) && $output)
            {

                //Load Authorization Token Library
                $this->load->library('Authorization_Token');

                //Generate Token
                $token_data = array(
                    'id'        => $output[0]['id'], //Recommend for Token
                    'username'  => $output[0]['username'],
                    'email'     => $output[0]['email'],
                    'full_name' => $output[0]['full_name'],
                    'insert'    => $output[0]['insert'],
                    'update'    => $output[0]['update'],
                    'time'      => time() //Recommend for Token
                );

                $user_token = $this->authorization_token->generateToken($token_data);

                //print_r($this->authorization_token->userData()); 
                //print_r($this->authorization_token->validateToken()); 
                //exit();

                $return_data = array(

                    'id'        => $output[0]['id'],
                    'email'     => $output[0]['email'],
                    'full_name' => $output[0]['full_name'],
                    'insert'    => $output[0]['insert'],
                    'token'     => $user_token

                );

                //Login Success
                $massage = array(
                    'status'    => TRUE,
                    'data'      => $return_data,
                    'massage'   => 'User Login Successful'
                );

                $this->response($massage, REST_Controller::HTTP_OK);
            }
            else
            {
                //Login Error
                $massage = array(
                    'status'    => FALSE,
                    'massage'   => 'Invalid Username or Password'
                );

                $this->response($massage, REST_Controller::HTTP_NOT_FOUND);
            }
        }

    }

    /**  
     * Fetch All User Data
     * @method : GET 
     * @link : users/all
     */
    public function fetch_all_users_get(){

        header("Access-Controll-Allow-Origin: *");

        $data = $this->Users_Model->fetch_all_users();

        $this->response($data);

    }
 
}