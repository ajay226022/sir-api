<?php
ob_start();
header( 'Access-Control-Allow-Origin: *' );
header( 'Access-Control-Allow-Methods: POST, GET, OPTIONS, PUT, DELETE' );
header( 'Access-Control-Allow-Credentials: true' );

define('SITE_URL',site_url()); 
require_once( ABSPATH.'wp-admin/includes/user.php' ); 
require_once( ABSPATH . 'wp-admin/includes/image.php' );
require_once( ABSPATH . 'wp-admin/includes/file.php' ); 
require_once( ABSPATH . 'wp-admin/includes/media.php' ); 
define('ADMIN_EMAIL', 'admin@knoxweb.com');  
  
//require( ABSPATH . '/wp-load.php' );  
  //updateDeviceToken  
/**
 *  
 * @wordpress-plugin 
 * Plugin Name:       CRC Rest Api
 * Description:       This Plugin contain all rest api.
 * Version:           1.0
 * Author:            SS
 */ 
 
 
 use Firebase\JWT\JWT; 
 class CRC_REST_API extends WP_REST_Controller {
   	private $api_namespace;
	private $api_version;
	private $required_capability;
	public $user_token;
	public $user_id;
	public function __construct() {
		$this->api_namespace = 'api/v';
		$this->api_version = '1';
		$this->required_capability = 'read';   
		$this->init();
		/*------- Start: Validate Token Section -------*/
		$headers = getallheaders(); 
		if (isset($headers['Authorization'])) { 
        	if (preg_match('/Bearer\s(\S+)/', $headers['Authorization'], $matches)) { 
            	$this->user_token =  $matches[1]; 
        	} 
        }
        /*------- End: Validate Token Section -------*/
	}
	
	private function successResponse($message='',$data=array(),$total = array()){ 
        $response =array();
        $response['status'] = "success";
        $response['message'] =$message;
        $response['data'] = $data;
        if(!empty($total)){
            $response['total'] = $total;
        }
        return new WP_REST_Response($response, 200);  
    }
    private function errorResponse($message='',$type='ERROR' , $statusCode=200){
        $response = array();
        $response['status'] = "error";
        $response['error_type'] = $type;
        $response['message'] =$message;
        return new WP_REST_Response($response, $statusCode); 
    } 
    
    public function register_routes() {  
		$namespace = $this->api_namespace . $this->api_version;
	    $privateItems = array('getUserProfile', 'updateUserProfile','getUserProfileData','getUserProfileById','updateUserByid', 'addProfile' ); //Api Name 
	    $publicItems  = array('register','retrivePassword','retrivePass','changePassword','aboutUs','getContactUs','contactUs','sendContactUs', 'getAvatar','getHelp','getHelpById','getPatientById', 'getCaregiver',
	    'addflush' , 'addfood','addcomment','addflagday','getjournal','getRecipe','getRecipebyCategory', 'addBlend', 'getBlend', 'addFavorites', 'getfavorites','removeFavrecipe','getcatinfo', 'getcatinfoById','getProducts','getallproduct','getproductById',
'ingredientinrecipe', 'getrecipeById', 'addshopping', 'getshopping', 'getshoppingById', 'deleteblend', 'getingredientbyid','getrecipecategorypage', 'getproductbysearch', 'ownblend', 'ownblendcalculation', 'getpendingrecipe', 'renovepatient');
		foreach($privateItems as $Item){
		  	register_rest_route( $namespace, '/'.$Item, array(
			   array( 
			       'methods' => 'POST', 
			       'callback' => array( $this, $Item), 
			       'permission_callback' => !empty($this->user_token)?'__return_true':'__return_false' 
			       ),
	    	    )  
	    	);  
		}
		
		foreach($publicItems as $Item){
		  	register_rest_route( $namespace, '/'.$Item, array(
			   array( 
			       'methods' => 'POST', 
			       'callback' => array( $this, $Item )
			       ),
	    	    )  
	    	);  
		}
		
		
	}
	
	
	public function init(){
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
		add_action( 'rest_api_init', function() {
			remove_filter( 'rest_pre_serve_request', 'rest_send_cors_headers' );
			add_filter( 'rest_pre_serve_request', function( $value ) {
				header( 'Access-Control-Allow-Origin: *' );
				header( 'Access-Control-Allow-Methods: POST, GET, OPTIONS, PUT, DELETE' );
				header( 'Access-Control-Allow-Credentials: true' );
				return $value;
			});
		}, 15 );
		$namespace = $this->api_namespace . $this->api_version;
		add_filter( 'jwt_auth_whitelist', function ( $endpoints ) {
            return array(
                '/wp-json/'.$namespace.'/v1/retrivePass',
            );
        } );
	}
	
	public function isUserExists($user)
    {
        global $wpdb;
        $count = $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM $wpdb->users WHERE ID = %d", $user));
        if ($count == 1) {return true;} else {return false;}
    }
        
	public function getUserIdByToken($token)
    {
        $decoded_array = array();
        $user_id = 0;
        if ($token) {
            try{
                $decoded = JWT::decode($token, JWT_AUTH_SECRET_KEY, array('HS256'));
                $decoded_array = (array) $decoded;
            }
            catch(\Firebase\JWT\ExpiredException $e){

                return false;
            }
        }
        if (count($decoded) > 0) {
            $user_id = $decoded_array['data']->user->id;
        }
        if ($this->isUserExists($user_id)) {
            return $user_id;
        } else {
            return false;
        }
    }
    
    function jwt_auth($data, $user) {
        unset($data['user_nicename']);
        unset($data['user_display_name']); 
        $site_url = site_url();
            $result = $this->getProfile( $user->ID );
            $tutorial = get_user_meta($user->ID,'tutorial',true);
            
            $result['token'] =  $data['token'];
            return $this->successResponse('User Logged in successfully',$result);
    }

    private function isValidToken(){
    	$this->user_id  = $this->getUserIdByToken($this->user_token);
    }
    
    
      public function renovepatient($request){
    global $wpdb;  
     $param = $request->get_params();
     $id = $param['patient_id'];
     wp_delete_post($param['patient_id'], true); 
     
    // $wpdb->DELETE table1, table2, table3 FROM table1 INNER JOIN table2 INNER JOIN table3 WHERE table1.userid = table2.userid AND table2.userid = table3.userid AND table1.userid=3
    echo $id;
     $wpdb->query($wpdb->prepare("DELETE blend_plans, favorites_recipe, food_journal_info,shopping_cart FROM blend_plans INNER JOIN favorites_recipe INNER JOIN food_journal_info,INNER JOIN shopping_cart WHERE blend_plans.patient_id = favorites_recipe.patient_id AND favorites_recipe.patient_id  = food_journal_info.patient_id AND blend_plans.patient_id= $id"));
     
    if(!empty($id)){
        return $this->successResponse('Your Recipe has been successfully submitted for review !',$param);
      }else{
        return $this->errorResponse('Not added');
    }
    }
    
    public function ownblend($request){
    global $wpdb;  
     $param = $request->get_params();
    $post_id = wp_insert_post(array(
      'post_title'=>$param['recipe_name'], 
      'post_type'=>'recipe', 
       'post_status'=>'publish',
      'post_content'=>$param['instructions'],
      'post_author'  =>$param['patient_id'],
    ));

    if ($post_id) {
      if(!empty($param['recipe_img'])){
                    $imgUrl = trim($param['recipe_img'],'"');
                    $attachment_file=uploadImage($imgUrl, $post_id);
                    update_post_meta($post_id,'_thumbnail_id',$attachment_file);
                }
        update_post_meta($post_id, 'status', 'trash');
        update_post_meta($post_id, 'product_info', json_encode($param['product']));
        update_post_meta($post_id, 'unit_info', json_encode($param['unit']));
        update_post_meta($post_id, 'quantity_info', json_encode($param['qty']));
        update_post_meta($post_id, 'energy_content_fluid_oz', $param['fluid_oz']);
        update_post_meta($post_id, 'energy_content_total_oz', $param['energy_content_total_oz']);
        update_post_meta($post_id, 'energy_content_total_calories', $param['energy_content_total_calories']);
        update_post_meta($post_id, 'energy_content_calories_per_oz', $param['energy_content_calories_per_oz']);
    }
    
    if(!empty($post_id)){
        return $this->successResponse('Your Recipe has been successfully submitted for review !',$param);
      }else{
        return $this->errorResponse('Not added');
    }
    }

     
    public function ownblendcalculation($request){
    global $wpdb;  
     $param = $request->get_params();
      $product_id = $param['product'];
        $qty        = $param['qty'];
        $unit       = $param['unit'];
        $fluid_oz      = $param['fluid_oz'];
        $nutrientsMerge  = array();
        $eMerge  = array();
    foreach($product_id as $key => $value){
        $query  = "select food_description from wp_standard_nutrients_wpg where food_id = '{$value}'";
        $produc_name = $wpdb->get_var($query);
        $arr['product']     = array('id' => $value, 'text' => $produc_name);
        $arr['qty']         = $qty[$key];
        $arr['unit']        = get_unit_data($value, $unit[$key]);
        $quantity           = $arr['qty'];
        $selectedUnit       = $unit[$key];
        $filterUnit         = array_merge(...array_filter(array_map(function($row) use($quantity, $selectedUnit){ 
            if($row['is_selected'] == 'selected'){
               $row['energy'] =   $row['energy']* $quantity;
               $row['size'] =   $row['size']* $quantity;
                foreach($row['nutrients'] as $k => $v){
                    $row['nutrients'][$k] = ($selectedUnit == 'pergram')?($v * $quantity/100) : $v * $quantity;
                }
                return $row;
            }
        }, $arr['unit'])));
        $nutrientsMerge     = array_merge_recursive($nutrientsMerge, $filterUnit['nutrients']);
  
 
        $i[]=$filterUnit;
        $total_calories = array_sum(array_column($i, 'energy'));
        $total_oz = array_sum(array_column($i, 'size'));
    }

        foreach($nutrientsMerge as $key => $value){ $nutrientsMerge[$key] =  (is_array($value)) ? array_sum($value):$value; }
        $results['nutrients']= $nutrientsMerge;
        $results['total_oz']= $total_oz;
        $results['total_calories']= $total_calories;
        $results['calories_per_oz']= $total_calories/$fluid_oz ;
    if(!empty($results)){
        return $this->successResponse('Nutritions fetched successfully',$results);
      }else{
        return $this->errorResponse('Not added');
    }
    }
    
    
    // Function for change password
    public function getProfile($id) {
    $data =[];
     	global $wpdb;
        $userInfo = get_user_by( 'ID', $id );
        $user_id = get_current_user_id();
          $args = array( 
        'post_type' => 'patients', 
        'post_status' => 'publish',
        'author' => $id,
    );
    $query = new WP_Query( $args ); 
    $posts = $query->get_posts();
    $output = array();
    foreach( $posts as $post ) {
       $thumbnail_id= get_post_meta($post->ID,'profile_pic',true);
       $result['post_id'] = $thumbnail_id;
        $result['post_id'] = $post->ID;
        $result['first_name'] = $post->first_name;
        $result['last_name'] = $post->last_name;
        $result['dob'] = $post->dob;
        $result['calorie_requirement'] = $post->calorie_requirement;
        $result['water_requirement'] = $post->water_requirement;
        $result['weight'] = $post->weight;
        $result['caregiver'] = $post->caregiver;
       $thumbnailImgUrl = get_post_meta($thumbnail_id,'_wp_attached_file',true);
       if(empty($thumbnail_id)){
            $result['patient_img'] = 'https://gravatar.com/avatar/dba6bae8c566f9d4041fb9cd9ada7741?d=identicon&f=y';
        } else {
           $result['patient_img'] = SITE_URL.'/wp-content/uploads/'.$thumbnailImgUrl;
        }
       if(!empty($result))
        $data[] = $result;
    }
  
        //maybe_serialize
        $result = array(
            'user_id'           => $userInfo->ID,
            'user_email'        => $userInfo->user_email,
            'user_name'         => $userInfo->user_name,
            'user_role'         => $userInfo->roles[0],
            'patient'           => $data,
        );
        if(!empty($userInfo)) {
            return $result;
        } else {
            return 0;
        }
    } 
    
    

      // Function for register user
    public function register($request){
      global $wpdb;
      $param = $request->get_params();
      // hospital data
      $first_name = $param['first_name'];
      $last_name = $param['last_name'];
      $dob = $param['dob'];
      $contact = $param['contact'];
      $userName = $first_name." ".$last_name;
      $agree = $param['agree'];
      $email = $param['email'];
      $password = $param['password'];
      $role = 'caregiver';

      if(email_exists($email)) {
          return $this->errorResponse('Email already exists.');
      }else{
            // User Info     
            $user_id = wp_create_user($email,$password,$email);
            update_user_meta($user_id,'user_name',$userName);
            update_user_meta($user_id,'agree',$agree);
            update_user_meta($user_id,'dob',$dob);
            update_user_meta($user_id,'contact',$contact);
            $user = new WP_User( $user_id );
            $user->set_role($role);
             $data = $this->getProfile($user_id);
            if(!empty($user_id)){
                return $this->successResponse('User registration successfull.'); 
            }else{
               return $this->errorResponse('Please try again.'); 
            }
        }
        
    }
    
    public function updateUserProfile($request){
        global $wpdb;
     	$param = $request->get_params();
        $this->isValidToken();
        $user_id = !empty($this->user_id)?$this->user_id:$param['user_id'];
        $first_name = $param['first_name'];
        $last_name = $param['last_name'];
        $dob = $param['dob'];
        $weight = $param['weight'];
        $calorie_requirement = $param['calorie_requirement'];
        $water_requirement = $param['water_requirement'];
        $caregiver = $param['caregiver'];
        $profile_pic = $param ['profile_pic'];
        $avatar_id = $param['avatar_id'];
        $patient_id = $param['id'];
         if(!empty($user_id)){
            $postId  = wp_update_post(array(
                   'ID'   => $patient_id ,
                  'post_type'=>'patients', 
                  'post_author'   =>$user_id,
                  'post_status'  =>'publish'
            ));
            update_post_meta($postId, 'first_name', $first_name);
            update_post_meta($postId, 'last_name', $last_name);
            update_post_meta($postId, 'dob', date('d/m/Y',strtotime($dob)));
            update_post_meta($postId, 'weight', $weight);
            update_post_meta($postId, 'calorie_requirement', $calorie_requirement);
            update_post_meta($postId, 'water_requirement', $water_requirement);
            update_post_meta($postId, 'caregiver', $caregiver);
        
            if(!empty($_FILES['profile_pic'])){
                    $userProfileImgId = media_handle_upload('', $user_id);
                    update_post_meta($postId,'profile_pic',$userProfileImgId);
                }
            if(!empty($avatar_id)){
                    update_post_meta($postId, 'profile_pic', $avatar_id);
            }  
           }
           if(!empty($postId)){
        return $this->successResponse('Profile Updated Successfully!');
      }else{
        return $this->errorResponse('No record found');
    }    
            
    }          
        
    
     public function updateUserByid($request){
        	global $wpdb;
        	$photos=array();
        	$param = $request->get_params();
            $this->isValidToken();
            $files_photo = $_FILES['add_photos'];
            $user_id = !empty($this->user_id)?$this->user_id:$param['user_id'];
            
            if(empty($user_id)){
                return errorResponse('Please enter the valid token.');
            } 
            else{
            if(!empty($files_photo['name'] )){
                foreach ($files_photo['name'] as $key => $value) {
                    if ($files_photo['name'][$key]) {
                            $file = array(
                                'name' => $files_photo['name'][$key],
                                'type' => $files_photo['type'][$key],
                                'tmp_name' => $files_photo['tmp_name'][$key],
                                'error' => $files_photo['error'][$key],
                                'size' => $files_photo['size'][$key]
                            );
                            $_FILES = array("upload_file" => $file);
                            $photos[] = media_handle_upload("upload_file", 0);
                        }
                    }
                update_user_meta($user_id,'family_photo',maybe_serialize($photos));  
                }    
         if(!empty($photos)){
        	    	return $this->successResponse('User profile updated successfully', $result);
        } else {
        	    	return $this->errorResponse('No record found');
        	    }
            }
    }


public function getAvatar(){
    $args = array( 
        'post_type' => 'avatars', 
        'post_status' => 'publish', 
    );
    $query = new WP_Query( $args ); 
    $posts = $query->get_posts();
    $output = array();
    foreach( $posts as $post ) {
       $thumbnail_id= get_post_meta($post->ID,'_thumbnail_id',true);
       $thumbnailImgUrl = get_post_meta($thumbnail_id,'_wp_attached_file',true);
       $res['post_id'] = $thumbnail_id;
       if(empty($thumbnail_id)){
            $res['avatar_img'] = 'https://gravatar.com/avatar/dba6bae8c566f9d4041fb9cd9ada7741?d=identicon&f=y';
        } else {
           $res['avatar_img'] = SITE_URL.'/wp-content/uploads/'.$thumbnailImgUrl;
        }
        
        $data[] = $res;
    }
    if(!empty($data)){
        return $this->successResponse('',$data);
      }else{
        return $this->errorResponse('No record found');
    }
}

public function getHelp(){
    $args = array( 
        'post_type' => 'help', 
        'post_status' => 'publish', 
        'posts_per_page' => -1
    );
    $query = new WP_Query( $args ); 
    $posts = $query->get_posts();
    $output = array();

    foreach( $posts as $post ) {
          $results['post_id'] = $post->ID;
        //   $results['post_content'] = $post->post_content;
          $results['post_title'] = $post->post_title;
         $thumbnail_id= get_post_meta($post->ID,'gallery_image',true);
         $gallery_images = maybe_unserialize($thumbnail_id);
         $imgArry = array();
         foreach ($gallery_images  as $gallery_imagesId ) {
            $attachmentsimg = get_post_meta($gallery_imagesId,'_wp_attached_file',true);
            $img = SITE_URL.'/wp-content/uploads/'.$attachmentsimg;
            $imgArry[] = $img;
         }
          $video= get_post_meta($post->ID,'video',true);
       $videoImgUrl = get_post_meta($video,'_wp_attached_file',true);
        $res = SITE_URL.'/wp-content/uploads/'.$videoImgUrl;
         
         $results['video'] = $res;
         $results['gallery_image'] = $imgArry;
        $data[] = $results;
    }
    if(!empty($data)){
        return $this->successResponse('',$data);
      }else{
        return $this->errorResponse('No record found');
    }
}

 public function getHelpById($request){
    $args = array(
      'p' => $request['id'],
      'post_type' => 'help',
    );
    if ( ! $post = get_post( $request['id'] ) ) {
      return new WP_Error( 'invalid_id', 'Please define a valid post ID.' );
    }
    $query = new WP_Query($args);
    if ($query -> have_posts()) {
      $query->the_post();
      $post = get_post(get_the_ID());
      $id = get_the_ID();
      $title = $post->post_title;
        $thumbnail_id= get_post_meta($post->ID,'gallery_image',true);
         $gallery_images = maybe_unserialize($thumbnail_id);
         $imgArry = array();
         foreach ($gallery_images  as $gallery_imagesId ) {
            $attachmentsimg = get_post_meta($gallery_imagesId,'_wp_attached_file',true);
            $img = SITE_URL.'/wp-content/uploads/'.$attachmentsimg;
            $imgArry[] = $img;
             }
         
        $video= get_post_meta($post->ID,'video',true);
        $videoImgUrl = get_post_meta($video,'_wp_attached_file',true);
        $res = SITE_URL.'/wp-content/uploads/'.$videoImgUrl;
        $results['id'] = $id;
        $results['title'] = $title;
        $results['post_content'] = $post->post_content;
        $results['video'] = $res;
        $results['gallery_image'] = $imgArry;
        $data[] = $results;
    }
    wp_reset_postdata();
       if(!empty($data)){
           return $this->successResponse('',$data);
           }else{
          return $this->errorResponse('No record found');
          }
    }

public function getcatinfo(){
    $args = array( 
        'post_type' => 'recipecat_info', 
        'post_status' => 'publish', 
        'posts_per_page' => -1
    );
    $query = new WP_Query( $args ); 
    $posts = $query->get_posts();
    $output = array();

        foreach( $posts as $post ) {
          $results['recipe_id'] = $post->ID;
          $results['post_content'] = $post->post_content;
          $results['category_title'] = $post->post_title;
             $thumbnail_id= get_post_meta($post->ID,'_thumbnail_id',true);
            $attachmentsimg = get_post_meta($thumbnail_id,'_wp_attached_file',true);
            $img = SITE_URL.'/wp-content/uploads/'.$attachmentsimg;
            $results['recipe_image'] = $img;
            $data[] = $results;
    }
    if(!empty($data)){
        return $this->successResponse('',$data);
      }else{
        return $this->errorResponse('No record found');
    }
}

//  public function getcatinfoById($request){
//           $post_title = 'Renal friendly';
// $post_id = get_page_by_title($post_title, OBJECT, 'recipecat_info');
//     $args = array(
//       'p' => $post_id,
//       'post_type' => 'recipecat_info',
//     );
   
//     $query = new WP_Query( $args ); 
//     $posts = $query->get_posts();
//     $output = array();
      
//       foreach( $posts as $post ) {
//           $results['recipe_id'] = $post->ID;
//           $results['post_content'] = $post->post_content;
//           $results['category_title'] = $post->post_title;
//              $thumbnail_id= get_post_meta($post->ID,'_thumbnail_id',true);
//             $attachmentsimg = get_post_meta($thumbnail_id,'_wp_attached_file',true);
//             $img = SITE_URL.'/wp-content/uploads/'.$attachmentsimg;
//             $results['recipe_image'] = $img;
//             $data[] = $results;
//     }
   
//       if(!empty($data)){
//           return $this->successResponse('',$data);
//           }else{
//           return $this->errorResponse('No record found');
//           }
//     }

 public function getrecipecategorypage($request){
     $post_title = $request['title'];
$post = get_page_by_title($post_title, OBJECT, 'recipecat_info');
      $title = $post->post_title;
     $thumbnail_id= get_post_meta($post->ID,'_thumbnail_id',true);
            $attachmentsimg = get_post_meta($thumbnail_id,'_wp_attached_file',true);
            $img = SITE_URL.'/wp-content/uploads/'.$attachmentsimg;
        $results['id'] = $post->ID ;
        $results['recipe_image'] = $img;
        $results['title'] = $title;
        $results['post_content'] = $post->post_content;
        $data[] = $results;
 if(!empty($data)){
          return $this->successResponse('',$data);
          }else{
          return $this->errorResponse('No record found');
          }
    }



 public function getPatientById($request){
    $args = array(
      'p' => $request['id'],
      'post_type' => 'patients',
    );
    
    if ( ! $post = get_post( $request['id'] ) ) {
      return new WP_Error( 'invalid_id', 'Please define a valid post ID.' );
    }
    $query = new WP_Query($args);
     $args = array(
          'role'    => 'caregiver',
           );
        $users = get_users( $args );
     foreach ( $users as $user ) {
             $id = $user->id;
             $result['caregiver_id'] = $id;
        
          }

    if ($query -> have_posts()) {
      $query->the_post();
      $post = get_post(get_the_ID());
      $id = get_the_ID();
      $title = $post->post_title;
        $thumbnail_id= get_post_meta($post->ID,'profile_pic',true);
        $result['patient_id'] = $post->ID;
        $result['first_name'] = $post->first_name;
        $result['last_name'] = $post->last_name;
        $result['dob'] = $post->dob;
        $result['calorie_requirement'] = $post->calorie_requirement;
        $result['water_requirement'] = $post->water_requirement;
        $result['weight'] = $post->weight;
        $result['caregiver'] = $post->caregiver;
      $thumbnailImgUrl = get_post_meta($thumbnail_id,'_wp_attached_file',true);
      if(empty($thumbnail_id)){
            $result['patient_img'] = 'https://gravatar.com/avatar/dba6bae8c566f9d4041fb9cd9ada7741?d=identicon&f=y';
        } else {
          $result['patient_img'] = SITE_URL.'/wp-content/uploads/'.$thumbnailImgUrl;
        }
    }
    wp_reset_postdata();
       if(!empty($result)){
        return $this->successResponse('',$result);
      }else{
        return $this->errorResponse('No record found');
    }
    }


    public function getcaregiver(){
         $args = array(
          'role'    => 'caregiver',
          'orderby' => 'user_nicename',
           'order'   => 'ASC'
           );
        $users = get_users( $args );
     foreach ( $users as $user ) {
             $id = $user->id;
             $first_name = $user->first_name;
             $last_name = $user->last_name;
             $results['id'] = $id;
             $results['full_name'] =trim($first_name.' '.$last_name);
             $data[] = $results;
          }
       if(!empty($data)){
        return $this->successResponse('',$data);
      }else{
        return $this->errorResponse('No record found');
    }
     }

    
    public function aboutUs($request){
         $args = array(
      'p' => $request['id'],
      'post_type' => 'page',
    );
    if ( ! $post = get_post( $request['id'] ) ) {
      return new WP_Error( 'invalid_id', 'Please define a valid post ID.' );
    }

    $query = new WP_Query($args);
    if ($query -> have_posts()) {
      $query->the_post();
      $post = get_post(get_the_ID());
      $id = get_the_ID();
      $title = $post->post_title;
        $results['id'] = $id;
        $results['title'] = $title;
        $results['post_content'] = $post->post_content;
        $data[] = $results;
    }
    wp_reset_postdata();
       if(!empty($data)){
        return $this->successResponse('',$data);
      }else{
        return $this->errorResponse('No record found');
    }

    }
    
    public function getContactUs($request){
         global $wpdb;
         $rs['options_contentUs']     = get_option( 'options_contact_us' );
         $option_contentImg           = get_option( 'options_contact_featured_image' );
         if(!empty($option_contentImg)){
           $imgdata  = get_post_meta($option_contentImg);
           $rs['other_content_featured'] = SITE_URL.'/wp-content/uploads/'.$imgdata['_wp_attached_file'][0]; 
        }else{
           $rs['other_content_featured'] = SITE_URL."/wp-content/uploads/2022/05/parking2-min.jpeg"; 
        }
        if(!empty($rs)){
            return $this->successResponse('Get all content List successfully.',$rs);
          }else{
            return $this->errorResponse('No record found');
        }
    }
    

    public function sendContactUs($request){
        global $wpdb;
        $param = $request->get_params(); 
        $this->isValidToken();
        $full_name = $param['full_name'];
        $user_email = $param['user_email'];
        $user_phone = $param['phone'];
        $user_message = $param['message'];
        $adminEmail = get_bloginfo('admin_email');
        if(!empty($adminEmail)){
            $message = __('Hello ,') . "<br><br>";
            $message .=__('<h3>User Name</h3><big><b> '.$user_email.'<b></big>')."<br><br>";
            $message .=__('<h3>User Phone</h3><big><b> '.$user_phone.'<b></big>')."<br><br>";
            $message .=__('<h3>Message</h3><big><p> '.$user_message.'<p></big>')."<br><br>";
            $message .= __('Sincerely') . "<br>";
            $message .= __('Support Team') . "<br>";
            $headers = array('Content-Type: text/html; charset=UTF-8');
            $subject = "Contact Form for Blended Feeding Tube Helper";
            $sent = wp_mail($adminEmail, $subject, $message, $headers);
            
            return $this->successResponse('Contact information sent successfully.');    
            
        }else{
          return $this->errorResponse('Please try again.');  
        }
    }
    
    public function getUserProfileById($request){
        $param = $request->get_params();
        $this->isValidToken();
        $id = !empty($this->user_id)?$this->user_id:$param['user_id'];
        $userInfo = get_user_by( 'ID', $id );
        $first_name = get_user_meta( $id, 'first_name', true );
        $address = !empty($address)?$address:'';
        $wp_user_profile = get_user_meta($id, 'profile_img' , true );
        $profile_pic_link = get_post_meta($wp_user_profile,'_wp_attached_file',true);
        
        if(empty($wp_user_profile)){
            $profile_img_link = 'https://gravatar.com/avatar/dba6bae8c566f9d4041fb9cd9ada7741?d=identicon&f=y';
        } else {
            $profile_img_link = SITE_URL.'/wp-content/uploads/'.$profile_pic_link;
        }
        $result = $this->getProfile($id);
        
        if(!empty($userInfo)) {
            return $this->successResponse('',$result);
        } else {
           return $this->errorResponse('Please try again.');
        }
    }
    
    
    public function changePassword($request){
    	$param = $request->get_params();
       // $this->isValidToken();
        // $user_id = !empty($this->user_id)?$this->user_id:$param['user_email'];
        $user_data = get_user_by('email', trim($param['user_email'])); 
        $user_id = $user_data->ID;
       
        $new_password = $param['new_password'];
        $con_password = $param['con_password'];
        $user     = get_userdata( $user_id );
        if(empty($user_id)) {
            return $this->errorResponse('Please enter the valid token.');
        } else if($new_password!=$con_password){
            return $this->errorResponse('Please enter same Password.'); 
        } else{
    
            $udata['ID'] = $user->data->ID;
            $udata['user_pass'] = $new_password;
            $uid = wp_update_user( $udata );
    
            if($uid){
                return $this->successResponse('Password changed successfully');
            } else {
                return $this->errorResponse('An un-expected error');
            }
        }
    }
    

    
    
    
        // Function for adding patient-profile
    public function addProfile($request){
    	global $wpdb;
        	$param = $request->get_params();
            $this->isValidToken();
            $user_id = !empty($this->user_id)?$this->user_id:$param['user_id'];
            if(empty($user_id)){
                return errorResponse('Please enter the valid token.');
            } 
              // Partient data
           $first_name = $param['first_name'];
           $last_name = $param['last_name'];
           $dob = $param['dob'];
           $weight = $param['weight'];
           $calorie_requirement = $param['calorie_requirement'];
           $water_requirement = $param['water_requirement'];
           $caregiver = $param['caregiver'];
           $profile_pic = $param ['profile_pic'];
           $avatar_id = $param['avatar_id'];
            //patient info
          if(!empty($user_id)){
            $patientName = $first_name.''.$last_name;
            $postId  = wp_insert_post(array(
                  'post_title'=>$patientName, 
                  'post_type'=>'patients', 
                  'post_author'   =>$user_id,
                  'post_status'  =>'publish'
            ));
            update_post_meta($postId, 'first_name', $first_name);
            update_post_meta($postId, 'last_name', $last_name);
            update_post_meta($postId, 'dob', $dob);
            update_post_meta($postId, 'weight', $weight);
            update_post_meta($postId, 'calorie_requirement', $calorie_requirement);
            update_post_meta($postId, 'water_requirement', $water_requirement);
            update_post_meta($postId, 'caregiver', $caregiver);
            if(!empty($_FILES['profile_pic'])){
                 $userProfileImgId = media_handle_upload('profile_pic', $user_id);
                 update_post_meta($postId,'profile_pic',$userProfileImgId);
                }
            if(!empty($avatar_id)){
                    update_post_meta($postId, 'profile_pic', $avatar_id);
            }  
           
          $data = $this->getProfile($user_id);
            if(!empty($user_id)){
                return $this->successResponse('User added successfully.'); 
            }else{
              return $this->errorResponse('Please try again.'); 
            }
        }
    }
    
        public function addflush($request){
    	global $wpdb;
        	$param = $request->get_params();
            $this->isValidToken();
            $user_id = !empty($this->user_id)?$this->user_id:$param['user_id'];
            if(empty($user_id)){
                return errorResponse('Please enter the valid token.');
            } 
               // flush data
           $time = $param['time'];
           $amount = $param['amount'];
           $patient_id = $param['patient_id'];
           $journal_type = $param['journal_type'];
            
             $tablename= 'food_journal_info';     
             $data=array(
                'time' => $time, 
                'amount' => $amount,
                'patient_id' => $patient_id,
                'journal_type' => $journal_type,
                   );
            $wpdb->insert( $tablename, $data);
          
         if(!empty($data)){
        return $this->successResponse('flush added!',$data);
      }else{
        return $this->errorResponse('No data found!');
    }
    }

     public function addcomment($request){
    	global $wpdb;
        	$param = $request->get_params();
            $this->isValidToken();
            $user_id = !empty($this->user_id)?$this->user_id:$param['user_id'];
         
            // flush data
           $time = $param['time'];
           $comment = $param['comment'];
           $patient_id = $param['patient_id'];
           $journal_type = $param['journal_type'];
           $tablename= 'food_journal_info'; 
               if(empty($patient_id)){
              return $this->errorResponse('Please select patient profile!.');
                
            }
               $id = $wpdb->get_var( "SELECT id FROM food_journal_info where patient_id= $patient_id  AND Date(time) = Date('$time') AND journal_type='addcomment'");
             $data=array(
                'time' => $time, 
                'journal_comment' => $comment,
                'patient_id' => $patient_id,
                'journal_type' => $journal_type,
                   );
      if(empty ($id)) {      
            $wpdb->insert( $tablename, $data);
           }
          elseif(!empty($id)){
                $wpdb->query($wpdb->prepare("UPDATE food_journal_info SET journal_comment = '".$comment."' WHERE id ='".$id."' "));  
          }
         if(!empty($data)){
        return $this->successResponse('comment added!',$data);
      }   
      else{
        return $this->errorResponse('No data found!');
    }
    
    }


     public function addflagday($request){
    	global $wpdb;
        	$param = $request->get_params();
            $this->isValidToken();
            $user_id = !empty($this->user_id)?$this->user_id:$param['user_id'];
            if(empty($user_id)){
                return errorResponse('Please enter the valid token.');
            } 
              // flush data
          $time = $param['time'];
          $flagday_color = $param['flagday_color'];
          $patient_id = $param['patient_id'];
          $journal_type = $param['journal_type'];
          $id = $wpdb->get_var( "SELECT id FROM food_journal_info where patient_id= $patient_id  AND Date(time) = Date('$time') AND journal_type='flagday'");
             $tablename= 'food_journal_info';     
             $data=array(
                'time' => $time, 
                'flagday_color' => $flagday_color,
                'patient_id' => $patient_id,
                'journal_type' => $journal_type,
                  );
           if(empty ($id)) {      
            $wpdb->insert( $tablename, $data);
           }
          elseif(!empty($id)){
                $wpdb->query($wpdb->prepare("UPDATE food_journal_info SET flagday_color = '".$flagday_color."' WHERE id ='".$id."' "));  
          }
         if(!empty($data)){
        return $this->successResponse('Flagday added!',$data);
      }else{
        return $this->errorResponse('No data found!');
    }
    }




 public function getingredientbyid($request){
         $args = array(
      'p' => $request['id'],
      'post_type' => 'product',
    );
    if ( ! $post = get_post( $request['id'] ) ) {
      return new WP_Error( 'invalid_id', 'Please define a valid post ID.' );
    }
    $query = new WP_Query($args);
    
      $query->the_post();
      $posts = get_post(get_the_ID());
      $id = get_the_ID();
      $title = $post->post_title;
      $results['id'] = $id;
      $results['title'] = $title;
      $results['post_content'] = $post->post_content;
      foreach( $posts as $post ) {
          $nutritional_content = get_field('nutritional_content',  $post->ID);
          $nutritional_content = array_map(function($row){
              $arr['energy_id'] = $row['nutritions'];
              $arr['energy_name'] = get_the_title($row['nutritions']);
              $arr['unit'] = $row['amount'];
              return $arr;
          }, $nutritional_content);
          
             $results['energy_content'] = $nutritional_content;
//         if( get_field('nutritional_content',  $post->ID) ):
//         $counter = 0;
//         return get_field('nutritional_content',  $post->ID);
//       while( the_repeater_field('nutritional_content', $post->ID)):

// //this sets up the counter starting at 0
//     $id= get_field('nutritional_content_'.$counter.'_nutritions');
//     $rs['energy_id']= get_field('nutritional_content_'.$counter.'_nutritions');
//     $rs['energy_name']=get_the_title($id);
//     $rs['unit']= get_field('nutritional_content_'.$counter.'_amount');
//       $dat[] = $rs;
//     $counter++; // add one per row
//      endwhile;
//       endif;
       
     }

        $data[] = $results;
       if(!empty($data)){
           return $this->successResponse('',$data);
           }else{
          return $this->errorResponse('No record found');
          }
    }


        public function addfood($request){
    	global $wpdb;
        	$param = $request->get_params();
            $this->isValidToken();
            $user_id = !empty($this->user_id)?$this->user_id:$param['user_id'];
            if(empty($user_id)){
                return errorResponse('Please enter the valid token.');
            } 
               // food data
           $time = $param['time'];
           $amount = $param['amount'];
           $food_item = $param['food_item'];
           $patient_id = $param['patient_id'];
           $journal_type = $param['journal_type'];
             $tablename= 'food_journal_info';     
             $data=array(
                'food_item' => $food_item, 
                'time' => $time,
                'amount' => $amount,
                'patient_id' => $patient_id,
                'journal_type' => $journal_type,
                   );
             
            $wpdb->insert( $tablename, $data);
          
         if(!empty($data)){
        return $this->successResponse('food added!',$data);
      }else{
        return $this->errorResponse('No data found!');
    }
    }
    
      public function getjournal($request){
                 global $wpdb;
               	 $param = $request->get_params();
               	 $patient_id = $param['patient_id'];
               	 $start_date = $param['start_date'];
               	 $end_date = $param['end_date'];
               	    if(empty($end_date)){
                     $results = $wpdb->get_results( "SELECT * FROM food_journal_info where patient_id= $patient_id AND time>= '$start_date' ORDER BY time ASC");
                 foreach($results as $result){
                         $res['id']=$result->id;
                         $res['journal_type']=$result->journal_type;
                         $res['journal_datetime']=$result->time;
                         $res['journal_date']= date('Y-m-d',strtotime($res['journal_datetime']));
                         $res['journal_type']=$result->journal_type;
                         $res['amount']=$result->amount;
                         $res['journal_comment']=$result->journal_comment;
                         $res['flagday_color']=$result->flagday_color;
                         $res['food_item']=$result->food_item;
                         $res['patient_id']=$result->patient_id;
                         $data[]= $res;
                     }
            } 
              else{ 
            $blends=$wpdb->get_results ( "SELECT * FROM blend_plans where patient_id= $patient_id AND time >='$start_date' AND time <='$end_date' ORDER BY time ASC " );
              foreach($blends as $blend){
                         $re['blend_id']=$blend->id;
                         $re['blend_datetime']=$blend->time;
                         $re['blend_date']= date('Y-m-d',strtotime($re['blend_datetime']));
                         $re['blend_plan']=$blend->blend_plan;
                         $dat[]= $re;
                     }
         
             $results= $wpdb->get_results ( "SELECT * FROM food_journal_info where patient_id= $patient_id AND time BETWEEN  '$start_date' AND '$end_date' ORDER BY time ASC " );
                  foreach($results as $result){
                         $res['journal_type']=$result->journal_type;
                         $res['journal_datetime']=$result->time;
                         $res['journal_date']= date('Y-m-d',strtotime($res['journal_datetime']));
                         $res['journal_time']= date('h:i A',strtotime($res['journal_datetime']));
                         $res['journal_type']=$result->journal_type;
                         $res['amount']=$result->amount;
                         $res['journal_comment']=$result->journal_comment;
                         $res['flagday_color']=$result->flagday_color;
                         $product_id= $result->food_item;
                         $query  = "select food_description from wp_standard_nutrients_wpg   WHERE food_id=$product_id";
                        $sql1 = "SELECT `water`, `energy`, `total_protein`, `total_fat`, `total_carbohydrate`, `total_dietary_fiber`, `insoluble_dietary_fiber`, `soluble_dietary_fiber`, `calcium`, `iron`, `magnesium`, `phosphorus`, `potassium`, `sodium`, `zinc`, `copper`, `manganese`, `selenium`, `vitamin_C_ascorbic_acid`, `thiamin_vitamin_B1`, `riboflavin_vitamin_B2`,
                        `pantothenic_acid`, `vitamin_B6_pyridoxine_pyridoxyl_pyridoxamine`, `dietary_folate_Equivalents`, `vitamin_B12_cobalamin`, `vitamin_D_calciferol`, `vitamin_E_total_alpha_tocopherol`, `vitamin_K_phylloquinone`, `chlorine`, `total_saturated_fatty_acids`, `total_monounsaturated_fatty_acids`, `total_polyunsaturated_fatty_acids`, `total_frans_fatty_acids_trans`, `cholesterol`, `added_sugars_by_total_sugars`, 
                        `total_sugars`, `omega_3_fatty_acids`, `total_vitamin_A_activity_retinol_activity_equivalents`, `niacin_equivalents` FROM `wp_standard_nutrients_wpcps` WHERE food_id=$product_id";
                        $a1 = $wpdb->get_results($sql1);
                       
                        $sql2 = "select water_g, energy_g, total_protein_g, total_fat_g, total_carbohydrate_g, total_dietary_fiber_g, insoluble_dietary_fiber_g,
                        soluble_dietary_fiber_g_, calcium_mg, iron_mg, magnesium_mg, phosphorus_mg, potassium_mg, sodium_mg, zinc_mg, copper_mg, manganese_mg, selenium_mcg, 
                        vitamin_c_ascorbic_acid_mg, thiamin_vitamin_b1_mg, riboflavin_vitamin_b2_mg, pantothenic_acid_mg, vitamin_b6_ppp, `dietary_folate_quivalents_mcg`, `vitamin_b12_cobalamin_mcg`, 
                        `vitamin_b_calciferol_mcg`, `vitamin_e_total_alpha_tocopherol_mg`, `vitamin_k_phylloquinone_mcg`, `choline_mg`, `total_saturated_fatty_acids_sfa_g`, `total_monounsaturated_fatty_acids_mufa_g`, 
                        `total_polyunsaturated_fatty_acids_pufa_g`, `total_frans_fatty_acids_trans_g`, `cholesterol_mg`, `added_sugars_by_total_sugars_g`, 
                        `total_sugars_g`, `omega_3_fatty_acids_g`, `total_vitamin_a_activity_retinol_activity_equivalents_mcg`, `niacin_equivalents_mg` 
                        from wp_standard_nutrients_wpg WHERE food_id=$product_id";
                        
                        $a2 = $wpdb->get_results($sql2, ARRAY_A);
                        if(count($a2)>0){
                         $res['wpg'] =$a2[0];
                        //  $res['wpcps']=$a1[0];
                        }
                        else{
                          $res['wpg'] = [];
                        //   $res['wpcps'] =[];
                      } 
                        //  $res['unit']=get_unit_data($product_id);
                         $res['food_item']=$wpdb->get_var($query);
                         $res['patient_id']=$result->patient_id;
                         $res['blend']=$dat;
                         $data[]= $res;
                  }
        } 	 
         
       if(!empty($data)){
        return $this->successResponse('',$data);
      } else{
            
        return $this->errorResponse('No record found');
          }
    }
    
        
      public function getBlend($request){

        global $wpdb;
        $param = $request->get_params();
        $patient_id = $param['patient_id'];
        $start_date = $param['start_date'];
        $end_date = $param['end_date'];
        if(!empty($start_date)){
            $results = $wpdb->get_results( "SELECT * FROM blend_plans where patient_id= $patient_id AND Date(time) = '$start_date' ORDER BY time ASC");
            $nutrientsMerge  = array();
            $caloriesMerge   = array();
            foreach($results as $result){
                $res['id']=$result->id;
                $res['blend_datetime']=$result->time;
                $res['blend_date']= date('Y-m-d',strtotime($res['blend_datetime']));
                $blend_id = maybe_unserialize($result->blend_plan);
                foreach ($blend_id as $blend) {
                    $post = get_post($blend);
                    $rs['post_id'] = $blend;
                    $nutrients =$this->getnutrientsbyid($blend);
                    $calories= $post->energy_content_total_calories;
                    $total_oz= $post-> energy_content_total_oz * 28.34945;
                    $totalserv[]=$post-> energy_content_total_oz * 28.34945;
                    $totalcal[]=$post->energy_content_total_calories;
                    $rs['calories'] = $calories;
                    $rs['serving_size'] = $total_oz;
                    $rs['calories_density'] = $calories/$total_oz;
                    $rs['nutritions']=$nutrients;
                     $nutrientsMerge     = array_merge_recursive($nutrientsMerge, $nutrients);
                     $nutrientsdens      =$nutrientsMerge;
                     $caloriesMerge      =array_sum($totalcal);
                     $servingMerge       = array_sum($totalserv);
                    $rs['recipe_image'] = get_the_post_thumbnail_url($blend, 'thumbnail');
                    if(empty(  $rs['recipe_image'])){
                        $rs['recipe_image']='https://blendedft.betaplanets.com/wp-content/uploads/2022/09/recipe.png';
                    }
                        
                    $rs['recipe_name'] =get_the_title( $blend );
                    $dat[]=$rs;
                }
            
            foreach($nutrientsMerge as $key => $value){ $nutrientsMerge[$key] =  (is_array($value)) ? (array_sum($value)) : ($value); }
            foreach($nutrientsdens as $key => $value){ $nutrientsdens[$key] =  (is_array($value)) ? (array_sum($value)/$servingMerge *100 ) : ($value); }
                $res['total_serrving_size']=$servingMerge;
                $res['total_calories']= $caloriesMerge;
                $res['total_nutrition'] = $nutrientsMerge;
                $res['nutrition_density'] = $nutrientsdens;
                $res['blend_plan']=$dat;
                $res['patient_id']=$result->patient_id;
            }
        } 	 
        if(!empty($res)){
            return $this->successResponse('',$res);
        }else{
            return $this->errorResponse('No record found');
        }
    }
    
    // Function for get recipe
    public function getRecipe(){
       $args = array(
        'post_type' => 'recipe',
        'posts_per_page' => 6,
        'orderby' => 'date',
        'order' => 'DSC'
        );
    $query = new WP_Query( $args ); 
    $posts = $query->get_posts();
    $output = array();
    foreach( $posts as $post ) {
         $status= get_post_meta($post->ID,'status',true);
         if ($status !='trash'){
          $results['recipe_id'] = $post->ID;
          $results['post_content'] = $post->post_content;
          $results['recipe_name'] = $post->post_title;
             $thumbnail_id= get_post_meta($post->ID,'_thumbnail_id',true);
            $attachmentsimg = get_post_meta($thumbnail_id,'_wp_attached_file',true);
             if(empty( $attachmentsimg)){
                     $attachmentsimg ='/2022/09/recipe.png';
                }
            $img = SITE_URL.'/wp-content/uploads/'.$attachmentsimg;
            $results['recipe_image'] = $img;
            $recent[] = $results;
    }
    }
    
      $args = array( 
        'post_type' => 'recipe',
        'categories' => 'renal_friendly',
        'post_status' => 'publish',
        'posts_per_page' => -1
    );

    $query = new WP_Query( $args ); 
    $posts = $query->get_posts();
    $output = array();
    foreach( $posts as $post ) {
        
          $results['recipe_id'] = $post->ID;
          $results['post_content'] = $post->post_content;
          $results['recipe_name'] = $post->post_title;
             $thumbnail_id= get_post_meta($post->ID,'_thumbnail_id',true);
            $attachmentsimg = get_post_meta($thumbnail_id,'_wp_attached_file',true);
                 if(empty( $attachmentsimg)){
                     $attachmentsimg ='/2022/09/recipe.png';
                }
            $img = SITE_URL.'/wp-content/uploads/'.$attachmentsimg;
         $results['recipe_image'] = $img;
        $renal_friendly[] = $results;
    }

       $args = array( 
        'post_type' => 'recipe',
        'categories' => 'holiday_favorites',
        'post_status' => 'publish',
        'posts_per_page' => -1
    );
    $query = new WP_Query( $args ); 
    $posts = $query->get_posts();
    $output = array();
    foreach( $posts as $post ) {
          $results['recipe_id'] = $post->ID;
          $results['post_content'] = $post->post_content;
          $results['recipe_name'] = $post->post_title;
             $thumbnail_id= get_post_meta($post->ID,'_thumbnail_id',true);
             $attachmentsimg = get_post_meta($thumbnail_id,'_wp_attached_file',true);
                  if(empty( $attachmentsimg)){
                     $attachmentsimg ='/2022/09/recipe.png';
                }
             $img = SITE_URL.'/wp-content/uploads/'.$attachmentsimg;
             $results['recipe_image'] = $img;
             $holiday_favorites[] = $results;
    }
          $data['recent'] = $recent;
          $data['renal_friendly'] = $renal_friendly;
          $data['holiday_favorites'] = $holiday_favorites;
     
    if(!empty($data)){
        return $this->successResponse('',$data);
      }else{
        return $this->errorResponse('No record found');
       }
    }


// Function for get recipebycategory
    public function getRecipebyCategory($request){
        	global $wpdb;
        	$param = $request->get_params();
        	$paged  = !empty($param['paged']) ? $param['paged'] : 1;
        	if(!empty($param)){
            $args = array( 
                'post_type' => 'recipe',
                'categories' => $param['category'],
                'post_status' => 'publish',
            );
        $query = new WP_Query( $args );
        $data =array();
        $totalPost = $query->found_posts;
        $posts = $query->posts;
        foreach( $posts as $post ) {
             $status= get_post_meta($post->ID,'status',true);
         if ($status !='trash'){
              $results['recipe_id'] = $post->ID;
              $results['post_content'] = $post->post_content;
              $results['recipe_name'] = $post->post_title;
                 $thumbnail_id= get_post_meta($post->ID,'_thumbnail_id',true);
                $attachmentsimg = get_post_meta($thumbnail_id,'_wp_attached_file',true);
                     if(empty( $attachmentsimg)){
                     $attachmentsimg ='/2022/09/recipe.png';
                }
                $img = SITE_URL.'/wp-content/uploads/'.$attachmentsimg;
                $results['recipe_image'] = $img;
                $data[] = $results;
         }
        }
        	}
        	elseif(empty($param)){
        	     	$args = array(
        'post_type' => 'recipe',
        'posts_per_page' => -1,
        'orderby' => 'date',
        'order' => 'DSC'

        );
    $query = new WP_Query( $args ); 
    $posts = $query->get_posts();
    $output = array();
    foreach( $posts as $post ) {
              $status= get_post_meta($post->ID,'status',true);
         if ($status !='trash'){
          $results['recipe_id'] = $post->ID;
          $results['post_content'] = $post->post_content;
          $results['recipe_name'] = $post->post_title;
             $thumbnail_id= get_post_meta($post->ID,'_thumbnail_id',true);
            $attachmentsimg = get_post_meta($thumbnail_id,'_wp_attached_file',true);
                 if(empty( $attachmentsimg)){
                     $attachmentsimg ='/2022/09/recipe.png';
                }
            $img = SITE_URL.'/wp-content/uploads/'.$attachmentsimg;
            $results['recipe_image'] = $img;
            $data[] = $results;
    }
    }
        	}
       
        if(!empty($data)){
              return $this->successResponse('',$data,$totalPost);
          }else{
            return $this->errorResponse('No record found');
           }
        }
        

 // Function for get products
    public function getProducts(){
          $getAllCats = get_categories( array('taxonomy'=> 'product_cat', 'orderby'=> 'name',) );
          //$catArrayIds = array_values(array_column($getAllCats, 'term_id'));
          foreach($getAllCats as $catArrayIds){
              
            $arg = array(
                  'post_type' => 'product',
                  'numberposts' => -1,
                  'post_status' => 'publish',
                  'tax_query' => array(
                      array(
                          'taxonomy' => 'product_cat',
                          'terms' =>$catArrayIds->term_id,
                          'operator' => 'IN',
                          )
                      ),
                  );
                  
            $allProductLists = get_posts($arg);
            $catArrayIds->products = array_map(function($row){
                $arr['ID'] = $row->ID;
                $arr['title'] = $row->post_title;
                  $thumbnail_id= get_post_meta($row->ID,'_thumbnail_id',true);
                  $attachmentsimg = get_post_meta($thumbnail_id,'_wp_attached_file',true);
                  $img = SITE_URL.'/wp-content/uploads/'.$attachmentsimg;
                $arr['product_image'] = $img;
                return $arr;
            }, $allProductLists);
            
          }
          
        if(!empty( $getAllCats)){
              return $this->successResponse('', $getAllCats);
          }else{
            return $this->errorResponse('No record found');
           }
    }

public function getproductbysearch($request){
     global $wpdb;
    $param      = $request;
    $where      = '';
    $page       = (!empty($param['page']))?$param['page']:1;
    $per_page   = 5;
    $start_from = ($page - 1) * $per_page;
    $limit  = ' LIMIT ' . $start_from . ',' . $per_page;
    if(isset($param['q']) && !empty($param['q'])){
        $where = "where food_description LIKE '%{$param['q']}%'";
    }
    
    $query  = "select food_id as id, food_description as title from wp_standard_nutrients_wpg $where order by id asc";
    $quer     ="select food_id  from wp_standard_nutrients_wpg $where order by id asc";
    $count  = $wpdb->get_results($quer . $limit,ARRAY_A);
    // print_r($count);
    $results = $wpdb->get_results($query . $limit, ARRAY_A);
    
      foreach($results as $post){
          $k[] =get_unit_data($post[id]);
      
      }
      
           
    if(!empty($results)){
           return $this->successResponse('',$k);
           }else{
          return $this->errorResponse('No record found');
     }
}

 public function getallproduct($request){
   global $wpdb;
        // $sql = "select food_id, food_description, common_portion_size_description as text,  common_portion_size_unit as text from wp_standard_nutrients_wpcps";
     $sql = "select food_id, food_description,  common_portion_size_unit as text from wp_standard_nutrients_wpcps";
    $results = $wpdb->get_results($sql, ARRAY_A);

          
       if(!empty($results)){
           return $this->successResponse('',$results);
           }else{
          return $this->errorResponse('No record found');
          }
    }
    
 public function getproductById($request){
   global $wpdb;
  $param = $request->get_params();
   	 $product_id = $param['id'];
                $sql1 = "select  `water`, `energy`, `total_protein`, `total_fat`, `total_carbohydrate`,`total_dietary_fiber`, `insoluble_dietary_fiber`, `soluble_dietary_fiber`, `calcium`, `iron`, `magnesium`, `phosphorus`, `potassium`, `sodium`, 
                `zinc`, `copper`, `manganese`, `selenium`, `vitamin_C_ascorbic_acid`, `thiamin_vitamin_B1`, `riboflavin_vitamin_B2`, `pantothenic_acid`, `vitamin_B6_pyridoxine_pyridoxyl_pyridoxamine`, `dietary_folate_Equivalents`, `vitamin_B12_cobalamin`, `vitamin_D_calciferol`, `vitamin_E_total_alpha_tocopherol`, `vitamin_K_phylloquinone`, `chlorine`, `total_saturated_fatty_acids`, `total_monounsaturated_fatty_acids`, 
                `total_polyunsaturated_fatty_acids`, `total_frans_fatty_acids_trans`, `cholesterol`, `added_sugars_by_total_sugars`, `total_sugars`, `omega_3_fatty_acids`, 
                `total_vitamin_A_activity_retinol_activity_equivalents`, `niacin_equivalents`  from wp_standard_nutrients_wpcps  WHERE food_id=$product_id";
    $results['wpcps'] = $wpdb->get_results($sql1, ARRAY_A);
    
                $sql2 = "select water_g, energy_g, total_protein_g, total_fat_g, total_carbohydrate_g, total_dietary_fiber_g, insoluble_dietary_fiber_g,
                soluble_dietary_fiber_g_, calcium_mg, iron_mg, magnesium_mg, phosphorus_mg, potassium_mg, sodium_mg, zinc_mg, copper_mg, manganese_mg, selenium_mcg, 
                vitamin_c_ascorbic_acid_mg, thiamin_vitamin_b1_mg, riboflavin_vitamin_b2_mg, pantothenic_acid_mg, vitamin_b6_ppp, `dietary_folate_quivalents_mcg`, `vitamin_b12_cobalamin_mcg`, 
                `vitamin_b_calciferol_mcg`, `vitamin_e_total_alpha_tocopherol_mg`, `vitamin_k_phylloquinone_mcg`, `choline_mg`, `total_saturated_fatty_acids_sfa_g`, `total_monounsaturated_fatty_acids_mufa_g`, 
                `total_polyunsaturated_fatty_acids_pufa_g`, `total_frans_fatty_acids_trans_g`, `cholesterol_mg`, `added_sugars_by_total_sugars_g`, 
                `total_sugars_g`, `omega_3_fatty_acids_g`, `total_vitamin_a_activity_retinol_activity_equivalents_mcg`, `niacin_equivalents_mg` 
                from wp_standard_nutrients_wpg WHERE food_id=$product_id";
                
    $results['wpg'] = $wpdb->get_results($sql2, ARRAY_A);
       if(!empty($results)){
           return $this->successResponse('',$results);
           }else{
          return $this->errorResponse('No record found');
          }
    }


 public function getrecipeById($request){
    global $wpdb;
    $param = $request->get_params();
    $keyword = $param['id'];
    $args = array(
      'p' => $keyword,
      'post_type' => 'recipe',
     'post_status' => array(        
            'publish',                      
            'pending',                      
            'draft',                        
            'auto-draft',                   
            'future',                       
            'private',                     
            'inherit',                     
            ),
    );
    if ( ! $post = get_post( $request['id'] ) ) {
      return new WP_Error( 'invalid_id', 'Please define a valid post ID.' );
    }

   $query = new WP_Query( $args ); 
    $posts = $query->get_posts();

    foreach( $posts as $post ) {
        $product_id = ($post->product_info)?json_decode($post->product_info):array();
     
        $qty        = ($post->quantity_info)?json_decode($post->quantity_info):array();
        $unit       = ($post->unit_info)?json_decode($post->unit_info):array();
        $nutrientsMerge  = array();
       $results['recipe_id'] = $post->ID;
       $results['recipe_name'] = $post->post_title;
       $thumbnail_id= get_post_meta($post->ID,'_thumbnail_id',true);
       $attachmentsimg = get_post_meta($thumbnail_id,'_wp_attached_file',true);
       if(empty( $attachmentsimg)){
             $attachmentsimg ='/2022/09/recipe.png';
        }
            foreach($product_id as $key => $value){
        $query  = "select food_description from wp_standard_nutrients_wpg where food_id = '{$value}'";
        $produc_name = $wpdb->get_var($query);
        $arr['product']     = array('id' => $value, 'text' => $produc_name);
        $arr['qty']         = $qty[$key];
        $arr['unit']        = get_unit_data($value, $unit[$key]);
        $dat[] = $arr;
    }
       $img = SITE_URL.'/wp-content/uploads/'.$attachmentsimg;
       $results['recipe_image'] = $img;
       $results['ingredients'] = $dat;
       $results['total_nutrients'] = $this->getnutrientsbyid($post->ID);
       $results['total_calories'] = $post->energy_content_total_calories;
       $results['calories_per_oz'] = $post->energy_content_calories_per_oz;
       $results['about'] = $post->post_content;
      
       $data[] = $results;
    }
   if(!empty($data)){
    return $this->successResponse('',$data);
  }else{
    return $this->errorResponse('No record found');
      }
    }


 public function getpendingrecipe($request){
    global $wpdb;
    $param = $request->get_params();
    $keyword = $param['id'];
    $args = array(
      'p' => $keyword,
      'post_type' => 'recipe',
   
    );
    if ( ! $post = get_post( $request['id'] ) ) {
      return new WP_Error( 'invalid_id', 'Please define a valid post ID.' );
    }

   $query = new WP_Query( $args ); 
    $posts = $query->get_posts();

    foreach( $posts as $post ) {
        
        $product_id = ($post->product_info)?json_decode($post->product_info):array();
        $qty        = ($post->quantity_info)?json_decode($post->quantity_info):array();
        $unit       = ($post->unit_info)?json_decode($post->unit_info):array();
        $nutrientsMerge  = array();
           $results['recipe_id'] = $post->ID;
       $results['recipe_name'] = $post->post_title;
         $status= get_post_meta($post->ID,'status',true);
         if ($status='trash'){
                 $thumbnail_id= get_post_meta($post->ID,'_thumbnail_id',true);
       $attachmentsimg = get_post_meta($thumbnail_id,'_wp_attached_file',true);
       if(empty( $attachmentsimg)){
             $attachmentsimg ='/2022/09/recipe.png';
        }
       foreach($product_id as $key => $value){
        $query  = "select food_description from wp_standard_nutrients_wpg where food_id = '{$value}'";
        $produc_name = $wpdb->get_var($query);
        $arr['product']     = array('id' => $value, 'text' => $produc_name);
        $arr['qty']         = $qty[$key];
        $arr['unit']        = get_unit_data($value, $unit[$key]);
          if ($unit[$key] =='pergram'){
             $arr['unit']  =$this-> get_wpcunit($value, $unit[$key]);
        }
        $quantity           = $arr['qty'];
        $selectedUnit       = $unit[$key];
        $filterUnit         = array_merge(...array_filter(array_map(function($row) use($quantity, $selectedUnit){ 
            if($row['is_selected'] == 'selected'){
                foreach($row['nutrients'] as $k => $v){
                    $row['nutrients'][$k] = ($selectedUnit == 'pergram')?($v * $quantity/100) : $v * $quantity;
                }
                return $row;
            }
            if($row['is_selected'] == ''){
                foreach($row['nutrients'] as $k => $v){
                    $row['nutrients'][$k] = ($selectedUnit == 'pergram')?($v * $quantity/100) : $v * $quantity;
                }
                return $row;
            }
        }, $arr['unit'])));
        
        $nutrientsMerge     = array_merge_recursive($nutrientsMerge, $filterUnit['nutrients']);
        $dat[] = $arr;
    }
        foreach($nutrientsMerge as $key => $value){ $nutrientsMerge[$key] =  (is_array($value)) ? array_sum($value):$value; }
    
       $img = SITE_URL.'/wp-content/uploads/'.$attachmentsimg;
       $results['recipe_image'] = $img;
       $results['ingredients'] = $dat;
    //   $results['total_nutrients'] = $this->getnutrientsbyid($post->ID);
        $results['total_nutrients'] = $this->getnutrientsbyid($post->ID);
      $results['total_calories'] = $post->energy_content_total_calories;
      $results['calories_per_oz'] = $post->energy_content_nutrients_per_oz;
       $results['about'] = $post->post_content;
      
       $data[] = $results;
         }
   
    }
   if(!empty($data)){
    return $this->successResponse('',$data);
  }else{
    return $this->errorResponse('No record found');
      }
    }


// filter
public function ingredientinrecipe($request){
    global $wpdb;
    $param = $request->get_params();
    $keyword = $param['product_id'];
    $args = array(
    'posts_per_page' => -1,
    'post_type'      => 'recipe',
    'meta_query'     => array(
        array(
            // 'key'     => 'product_%_products',
            'compare' => 'LIKE',
            'value'   => $keyword,
        )
    )
);
    $query = new WP_Query( $args ); 
    $posts = $query->get_posts();
    $output = array();
    foreach( $posts as $post ) {
            $results['recipe_id'] = $post->ID;
          $results['recipe_name'] = $post->post_title;
           $thumbnail_id= get_post_meta($post->ID,'_thumbnail_id',true);
            $attachmentsimg = get_post_meta($thumbnail_id,'_wp_attached_file',true);
              if(empty( $attachmentsimg)){
                     $attachmentsimg ='2022/09/recipe.png';
                }
            $img = SITE_URL.'/wp-content/uploads/'.$attachmentsimg;
            $results['recipe_image'] = $img;
        $data[] = $results;
    }
       if(!empty($data)){
        return $this->successResponse('',$data);
      } else{
        return $this->errorResponse('No record found');
          }
}

     public function addBlend($request){
    	global $wpdb;
        	$param = $request->get_params();
            $this->isValidToken();
            $user_id = !empty($this->user_id)?$this->user_id:$param['user_id'];
            if(empty($user_id)){
                return errorResponse('Please enter the valid token.');
            } 
               //blend data
           $start_date = $param['start_date'];
           $blend_plan = $param['blend_plan'];
           $patient_id = $param['patient_id'];
           $type = $param['type'];
           	 
          $new_data = serialize($blend_plan); 
             $tablename= 'blend_plans'; 
             $data=array(
                  'time' => $start_date,
                  'blend_plan' => $new_data,
                  'patient_id' => $patient_id,
                  'type' => $type,
                  );
              
          if(!empty($start_date)){
           	        $date=date('Y-m-d',strtotime($start_date));
                    $results = $wpdb->get_var( "SELECT blend_plan FROM blend_plans where patient_id= $patient_id AND Date(time) = '$date' ORDER BY time ASC");
                    $prev_dataval = maybe_unserialize($results); 
           	    }
           	    
     if(!empty($prev_dataval)){
          $prev_dta  = array_unique(array_merge($prev_dataval,$blend_plan));
            $update_data = serialize($prev_dta); 
             $dat=array(
                  'time' => $start_date,
                  'blend_plan' => $update_data,
                  'patient_id' => $patient_id,
                  'type' => $type,
                  );
        $wpdb->query($wpdb->prepare("UPDATE $tablename SET blend_plan = '".$update_data."' WHERE Date(time) ='".$date."' "));
         if(!empty($dat)){
        return $this->successResponse('blend updated!',$dat);
      }else{
        return $this->errorResponse('No data found!');
    }
      }
          if(empty($prev_dataval)){
        $wpdb->insert( $tablename, $data);
    if(!empty($data)){
        return $this->successResponse('blend added!',$data);
      }else{
        return $this->errorResponse('No data found!');
    }
       }
}

public function deleteblend($request){
    global $wpdb;
    $param = $request->get_params();
     $id = $param['id'];
    $remove_id = $param['remove_id'];
    if(!empty($id)){
                     $results = $wpdb->get_var( "SELECT blend_plan FROM blend_plans where id= $id");
                      $prev_dataval = maybe_unserialize($results);
                      $newArray = array_diff($prev_dataval, array($remove_id));
                      $update_data = serialize($newArray); 
          	    }
          
         $wpdb->query($wpdb->prepare("UPDATE blend_plans SET blend_plan = '".$update_data."' WHERE id ='".$id."' "));  
          
if(!empty($update_data)){
        return $this->successResponse('List updated!',$update_data);
      }else{
        return $this->errorResponse('No data found!');
    }
       
}



     public function addFavorites($request){
    	global $wpdb;
        	$param = $request->get_params();
            $this->isValidToken();
            $user_id = !empty($this->user_id)?$this->user_id:$param['user_id'];
            if(empty($user_id)){
                return errorResponse('Please enter the valid token.');
            } 
               //blend data
           $patient_id = $param['patient_id'];
           $recipe_id = $param['recipe_id'];
            $new_data = serialize( $recipe_id); 
             $tablename= 'favorites_recipe'; 
             $data=array(
                  'patient_id' => $patient_id,
                  'recipe_id' => $new_data,
                  );
              
          if(!empty($patient_id)){
                     $results = $wpdb->get_var( "SELECT recipe_id FROM favorites_recipe where patient_id= $patient_id");
                     $pat_id = $wpdb->get_var( "SELECT patient_id FROM favorites_recipe where patient_id= $patient_id");
                      $prev_dataval = maybe_unserialize($results);
           	    }
           	    
     if(!empty($pat_id )){
          $prev_dta  = array_merge($prev_dataval, $recipe_id);
       
            $update_data = serialize($prev_dta); 
             $dat=array(
                 'patient_id' => $patient_id,
                  'recipe_id' => $update_data,
                  );
                 
        $wpdb->query($wpdb->prepare("UPDATE $tablename SET  recipe_id = '".$update_data."' where patient_id ='".$patient_id."' "));
         if(!empty($dat)){
        return $this->successResponse('Added to favorites!',$dat);
      }else{
        return $this->errorResponse('No data found!');
    }
      }
          if(empty($pat_id)){
        $wpdb->insert( $tablename, $data);
    if(!empty($data)){
        return $this->successResponse('Added to favorites!',$data);
      }else{
        return $this->errorResponse('No data found!');
    }
       }
}

     public function removeFavrecipe($request){
    	global $wpdb;
        	$param = $request->get_params();
            $this->isValidToken();
            $user_id = !empty($this->user_id)?$this->user_id:$param['user_id'];
            if(empty($user_id)){
                return errorResponse('Please enter the valid token.');
            } 
               //blend data
           $patient_id = $param['patient_id'];
           $recipe_id = $param['recipe_id'];
            $new_data = serialize( $recipe_id); 
             $tablename= 'favorites_recipe'; 
             $data=array(
                  'patient_id' => $patient_id,
                  'recipe_id' => $new_data,
                  );
              
          if(!empty($patient_id)){
                     $results = $wpdb->get_var( "SELECT recipe_id FROM favorites_recipe where patient_id= $patient_id");
                      $prev_dataval = maybe_unserialize($results);
           	    }
           	    
     if(!empty($prev_dataval)){
          $prev_dta  = array_diff($prev_dataval, $recipe_id);
            $update_data = serialize($prev_dta); 
             $dat=array(
                 'patient_id' => $patient_id,
                  'recipe_id' => $update_data,
                  );
                 
        $wpdb->query($wpdb->prepare("UPDATE $tablename SET  recipe_id = '".$update_data."' where patient_id ='".$patient_id."' "));
         if(!empty($dat)){
        return $this->successResponse('Removed from favorites!',$dat);
      }else{
        return $this->errorResponse('No data found!');
    }
      }

}

  public function getfavorites($request){
        global $wpdb;
        $param = $request->get_params();
        $patient_id = $param['patient_id'];
        $args = array( 
        'post_type' => 'recipe',
        'posts_per_page' => -1,
        'author' => $patient_id,
        );

        $query = new WP_Query( $args ); 
        $posts = $query->get_posts();

        $output = array();
        foreach( $posts as $post ) {
               $status= get_post_meta($post->ID,'status',true);
        if ( $status== 'trash'){
          $rs['recipe_id'] = $post->ID;
          $rs['post_content'] = $post->post_content;
          $rs['recipe_name'] = $post->post_title;
             $thumbnail_id= get_post_meta($post->ID,'_thumbnail_id',true);
            $attachmentsimg = get_post_meta($thumbnail_id,'_wp_attached_file',true);
                 if(empty( $attachmentsimg)){
                     $attachmentsimg ='/2022/09/recipe.png';
                }
            $img = SITE_URL.'/wp-content/uploads/'.$attachmentsimg;
         $rs['recipe_image'] = $img;
        $renal_friendly[] = $rs; 

               }

        }
    
   	    if(!empty($patient_id)){
         $results = $wpdb->get_results( "SELECT * FROM favorites_recipe where patient_id= $patient_id ");
         foreach($results as $result){
            $res['id']=$result->id;
            $recipe_id = maybe_unserialize($result->recipe_id);
            foreach ($recipe_id as $recipe) {
            $rs['recipe_id'] = $recipe;
            $attachmentsimg=get_the_post_thumbnail_url($recipe, 'thumbnail');
                if(empty( $attachmentsimg)){
                    $attachmentsimg ='https://blendedft.betaplanets.com/wp-content/uploads/2022/09/recipe.png';
                }
            $rs['recipe_image'] =$attachmentsimg ;
            $rs['recipe_name'] =get_the_title( $recipe );
            $dat[]=$rs;
            }
            $res['fav_recipe']=$dat;
           
         
             $res['patient_id']=$result->patient_id;
         }
           $res['pending_recipe']=$renal_friendly;
        } 	 
       if(!empty($res)){
        return $this->successResponse('',$res);
      }else{
        return $this->errorResponse('No record found');
          }
    }
    




     public function addShoppinglist($request){
    	global $wpdb;
        	$param = $request->get_params();
            $this->isValidToken();
            $user_id = !empty($this->user_id)?$this->user_id:$param['user_id'];
            if(empty($user_id)){
                return errorResponse('Please enter the valid token.');
            } 
               //blend data
           $patient_id = $param['patient_id'];
           $product_id = $param['product_id'];
           $quantity = $param['quantity'];
        //   $product['product_id']=    $product_id ;
        //   $product['quantity']=    $quantity ;
           
            $new_data = serialize($product_id); 
             $tablename= 'shopping_list'; 
             $data=array(
                  'patient_id' => $patient_id,
                  'product_id' => $new_data,
                  );
          if(!empty($patient_id)){
                     $results = $wpdb->get_var( "SELECT product_id FROM shopping_list where patient_id= $patient_id");
                     $pat_id = $wpdb->get_var( "SELECT patient_id FROM shopping_list where patient_id= $patient_id");
                      $prev_dataval = maybe_unserialize($results);
           	    }
           	    
     if(!empty($pat_id )){
          $prev_dta  = array_merge($prev_dataval, $product_id);
            $update_data = serialize($prev_dta); 
             $dat=array(
                 'patient_id' => $patient_id,
                  'product_id' => $update_data,
                  );
                 
        $wpdb->query($wpdb->prepare("UPDATE $tablename SET  product_id = '".$update_data."' where patient_id ='".$patient_id."' "));
         if(!empty($dat)){
        return $this->successResponse('Added to favorites!',$dat);
      }else{
        return $this->errorResponse('No data found!');
    }
      }
          if(empty($pat_id)){
        $wpdb->insert( $tablename, $data);
    if(!empty($data)){
        return $this->successResponse('Added to Shopping list!',$data);
      }else{
        return $this->errorResponse('No data found!');
    }
       }
}




  public function getshopping($request){
     global $wpdb;
     $param = $request->get_params();
   	 $patient_id = $param['patient_id'];
     if(!empty($patient_id)){
      $results = $wpdb->get_results( "SELECT * FROM shopping_cart where patient_id= $patient_id ");
     foreach($results as $result){
         $res['id']=$result->id;
         $res['quantity']=$result->quantity;
         $res['product_id']=$result->product_id;
         $res['mark']=$result->mark;
         $mark=$result->mark;
         $product_id = $result->product_id;
         $sql = "select food_description from wp_standard_nutrients_wpg WHERE food_id=$product_id";
         $ingredient_name = $wpdb->get_var($sql);
         $res['product_name']=$ingredient_name;
         $res['product_image'] = get_the_post_thumbnail_url($product_id, 'thumbnail');
         $data[]=$res;
        }
    } 	 
   if(!empty($data)){
    return $this->successResponse('',$data, $mark);
  }else{
    return $this->errorResponse('No record found');
      }
    }

 public function getshoppingById($request){
    global $wpdb;
    $param = $request->get_params();
    $id = $param['id'];
    $results = $wpdb->get_results( "SELECT * FROM shopping_cart where id= $id ");   	 
    foreach( $results as $result ) {
        $res['id']=$result->id;
        $product_id = $result->product_id;
        $res['quantity']=$result->quantity;
        $res['post_content']=get_post_field('post_excerpt',$product_id);
        $res['product_id']=$result->product_id;
        $res['mark']=$result->mark;
        $sql = "select food_description from wp_standard_nutrients_wpg WHERE food_id=$product_id";
        $ingredient_name = $wpdb->get_var($sql);
        $res['ingredient_name']=$ingredient_name;
        $res['ingredient_image'] = 'https://blendedft.betaplanets.com/wp-content/uploads/2022/09/recipe.png';
        
        $sql1 = "SELECT `water`, `energy`, `total_protein`, `total_fat`, `total_carbohydrate`, `total_dietary_fiber`, `insoluble_dietary_fiber`, `soluble_dietary_fiber`, `calcium`, `iron`, `magnesium`, `phosphorus`, `potassium`, `sodium`, `zinc`, `copper`, `manganese`, `selenium`, `vitamin_C_ascorbic_acid`, `thiamin_vitamin_B1`, `riboflavin_vitamin_B2`,
        `pantothenic_acid`, `vitamin_B6_pyridoxine_pyridoxyl_pyridoxamine`, `dietary_folate_Equivalents`, `vitamin_B12_cobalamin`, `vitamin_D_calciferol`, `vitamin_E_total_alpha_tocopherol`, `vitamin_K_phylloquinone`, `chlorine`, `total_saturated_fatty_acids`, `total_monounsaturated_fatty_acids`, `total_polyunsaturated_fatty_acids`, `total_frans_fatty_acids_trans`, `cholesterol`, `added_sugars_by_total_sugars`, 
        `total_sugars`, `omega_3_fatty_acids`, `total_vitamin_A_activity_retinol_activity_equivalents`, `niacin_equivalents` FROM `wp_standard_nutrients_wpcps` WHERE food_id=$product_id";
        $a1 = $wpdb->get_results($sql1);
       
        $sql2 = "select water_g, energy_g, total_protein_g, total_fat_g, total_carbohydrate_g, total_dietary_fiber_g, insoluble_dietary_fiber_g,
        soluble_dietary_fiber_g_, calcium_mg, iron_mg, magnesium_mg, phosphorus_mg, potassium_mg, sodium_mg, zinc_mg, copper_mg, manganese_mg, selenium_mcg, 
        vitamin_c_ascorbic_acid_mg, thiamin_vitamin_b1_mg, riboflavin_vitamin_b2_mg, pantothenic_acid_mg, vitamin_b6_ppp, `dietary_folate_quivalents_mcg`, `vitamin_b12_cobalamin_mcg`, 
        `vitamin_b_calciferol_mcg`, `vitamin_e_total_alpha_tocopherol_mg`, `vitamin_k_phylloquinone_mcg`, `choline_mg`, `total_saturated_fatty_acids_sfa_g`, `total_monounsaturated_fatty_acids_mufa_g`, 
        `total_polyunsaturated_fatty_acids_pufa_g`, `total_frans_fatty_acids_trans_g`, `cholesterol_mg`, `added_sugars_by_total_sugars_g`, 
        `total_sugars_g`, `omega_3_fatty_acids_g`, `total_vitamin_a_activity_retinol_activity_equivalents_mcg`, `niacin_equivalents_mg` 
        from wp_standard_nutrients_wpg WHERE food_id=$product_id";
        
        $a2 = $wpdb->get_results($sql2, ARRAY_A);
        if(count($a2)>0){
         $res['wpg'] =$a2[0];
         $res['wpcps']=$a1[0];

        }
        else{
          $res['wpg'] = [];
          $res['wpcps'] =[];
        }
        
        // $data[]=$res;
    }
   
    if(!empty($res)){
        return $this->successResponse('',$res);
    }else{
        return $this->errorResponse('No record found');
    }
}

    public function addshopping($request){
    	global $wpdb;
        $param = $request->get_params();
    //     $this->isValidToken();
    //     $user_id = !empty($this->user_id)?$this->user_id:$param['user_id'];
    //     if(empty($user_id)){
    //         return errorResponse('Please enter the valid token.');
    //     } 
           // food data
   $remove =$param['remove_id'];   
   $id = $param['id'];   
   $patient_id = $param['patient_id'];
   $product_id = $param['product_id'];
   $quantity = $param['quantity'];
   $mark_all = $param['mark_all'];
   $mark = $param['mark'];
     
    $tablename= 'shopping_cart';     
    $data=array(
        'patient_id' => $patient_id, 
        'product_id' => $product_id,
        'quantity' => $quantity,
        'mark' => $mark,
           );
    if(empty($id)){      
     $wpdb->insert( $tablename, $data);
            }
    if(!empty($id)){
        $wpdb->query($wpdb->prepare("UPDATE $tablename SET product_id = '".$product_id."', quantity = '".$quantity."',  mark = '".$mark."'   WHERE id ='".$id."' "));
         if(!empty($data)){
        return $this->successResponse('List updated!',$data);
      }else{
        return $this->errorResponse('No data found!');
    }
      }
    if(!empty($mark_all)){
        $wpdb->query($wpdb->prepare("UPDATE $tablename SET mark= '".$mark_all."'   WHERE patient_id ='".$patient_id."' "));
        
    if(!empty($mark_all)){
        return $this->successResponse('Marked as completed!',$mark_all);
      }else{
        return $this->errorResponse('No data found!');
    }
      }
    if(!empty($remove)){
       $wpdb->query($wpdb->prepare("DELETE FROM $tablename   WHERE id ='".$remove."' "));
    if(!empty($data)){
        return $this->successResponse('List updated!',$data);
      }else{
        return $this->errorResponse('No data found!');
    }
      }
    if(!empty($data)){
        return $this->successResponse('Added to list!',$data);
    }else{
        return $this->errorResponse('No data found!');
    }
    }
    

    // Function for get user profile
    public function getUserProfile($request){
    	global $wpdb;
    	$param = $request->get_params();
        $this->isValidToken();
        $user_id = !empty($this->user_id)?$this->user_id:$param['user_id'];
        if(empty($user_id)) {
            return errorResponse('Please enter the valid token.');
        } else {
            $result = $this->getProfile($user_id);
    	    if(!empty($result)){
    	    	return $this->successResponse('User Info fetched successfully', $result);
    	    } else {
    	    	return $this->errorResponse('No record found');
    	    }
        }
    }

    
    public function retrivePassword($request)
    {
            global $wpdb, $current_site;
            $param = $request->get_params();
            $user_login = sanitize_text_field($param['user_email']);
            $random_number = $param['random_number'];
            
            if (!is_email($user_login)) {
                return $this->errorResponse('Please provide valid email');
            }
            if (empty($user_login)) {
                 return $this->errorResponse('User email is empty');
            } elseif (strpos($user_login, '@')) {
                $user_data = get_user_by('email', trim($user_login));
            } else {
                $login = trim($user_login);
                $user_data = get_user_by('login', $login);
            }
            if (!$user_data) {
                 return $this->errorResponse('Email not matched with our records');
            }
            
            $user_email = $user_data->user_email;
            $digits = 4;
            $rand_pass = rand(1000,9999);
            $result_data = $wpdb->get_row("SELECT * FROM wp_random_num WHERE user_email='".$user_email."'");
         
            if($random_number==''){
            if($result_data->user_email == $user_email){
                    $str_update=array();
                    foreach ($param as $key => $value) {
                            if(!empty($value))
                            $str_update[]="$key='".$value."'";
                    }
                        $wpdb->query($wpdb->prepare("UPDATE wp_random_num SET  random_number = '".$rand_pass."' where user_email ='".$user_email."' "));
                    // $wpdb->query($wpdb->prepare("UPDATE wp_random_num SET ".implode(",", $str_update)." WHERE user_email='".$user_email."'"));
                    $message = "4 digit configuration code $result_data->random_number";
                    $message = __('Hello ,') . "<br><br>";
                    $message .= __('You recently requested for password chsnge <b>'.$user_email.'</b> on <b>Blended Feeding Tube Helper</b>.<br>To verify this
                    email address belongs to you, please enter the code below on the email on your confirmation page') . "<br><br>";
                    $message .=__('<big><b> '.$rand_pass.'<b></big>')."<br><br>";
                    $message .= __('Sincerely') . "<br>";
                    $message .= __('Support Team') . "<br>";
                    $headers = array('Content-Type: text/html; charset=UTF-8');
                    $subject = "Confirmation code for Blendeed Feeding Tube Helper";
                    $sent = wp_mail($user_email, $subject, $message, $headers);
                    return $this->successResponse('A Sepcial code has been sent to your email.Please input the code.',$user_email);    
                }else{
                    
                    $arg= array(
                        'user_email' => $user_login,
                        'random_number' => $rand_pass,
                    );
                    $insert_id = $wpdb->insert('wp_random_num', $arg);
                    $message = __('Hello ,') . "<br><br>";
                    $message .= __('You recently created account with email <b>'.$user_login.'</b> on <b>Parkly</b>.<br>To verify this
                    email address belongs to you, please enter the code below on the email on your confirmation page') . "<br><br>";
                    $message .=__('<big><b> '.$rand_pass.'<b></big>')."<br><br>";
                    $message .= __('Sincerely') . "<br>";
                    $message .= __('Support Team') . "<br>";
                    $headers = array('Content-Type: text/html; charset=UTF-8');
                    $subject = "Confirmation code for Blended Feeding Tube Helper";
                    $sent = wp_mail($user_login, $subject, $message, $headers);
                    return $this->successResponse('A Sepcial code has been sent to your email.Please input the code.',$user_login); 
                }
            }else if($result_data->random_number == $random_number){
                return $this->successResponse('Sepcial code have been corrected.');
            }else{
                return $this->errorResponse('Sepcial code is not correct.');
            }        
    }


    public function retrivePass($request){
        global $wpdb, $current_site;
        $param = $request->get_params();
        $user_login = sanitize_text_field($param['user_email']);
        
        if (!is_email($user_login)) {
            return $this->errorResponse('Please provide valid email');
        }else{
            $rand_num = rand(1000,9999);
            $link = 
            $message = __('Hello ,') . "\r\n\r\n";
            $message = __('Please copy verification code:') . "\r\n\r\n";
            $message .= sprintf(__('Verification code : %s'), $rand_num) . "\r\n\r\n";
            $message .= __('Thank you') . "\r\n\r\n";
            $title   ='Verification code';
            $user = get_user_by( 'email', $user_login);
            $id = $user->ID;
            $data['user_email']=$user_login;
            $data['rand_num']=$rand_num;
            $headers = array('Content-Type: text/html; charset=UTF-8');
            $subject = "Confirmation code for Sepsis";
            update_user_meta($id,'rand_num',$rand_num);
            wp_mail( $user_login, $title, $message, $headers );
            if ($message && !wp_mail($user_login, $title, $message,$headers)) {
               return $this->errorResponse('The e-mail could not be sent..');
            }else{
              return $this->successResponse('The e-mail sent..',$data);
            }
        }
    }
    
    
//     function getnutrientsbyid($id){
//       global $wpdb;
//     $args = array(
//       'p' => $id,
//       'post_type' => 'recipe',
//     );
//     if ( ! $post = get_post( $id ) ) {
//       return new WP_Error( 'invalid_id', 'Please define a valid post ID.' );
//     }
//       $query = new WP_Query( $args ); 
//       $posts = $query->get_posts();
//     foreach( $posts as $post ) {
//         $product_id = ($post->product_info)?json_decode($post->product_info):array();
//         $qty        = ($post->quantity_info)?json_decode($post->quantity_info):array();
//         $unit       = ($post->unit_info)?json_decode($post->unit_info):array();
//         $nutrientsMerge  = array();
//     foreach($product_id as $key => $value){
//         $query  = "select food_description from wp_standard_nutrients_wpg where food_id = '{$value}'";
//         $produc_name = $wpdb->get_var($query);
//         $arr['product']     = array('id' => $value, 'text' => $produc_name);
//         $arr['qty']         = $qty[$key];
//         $arr['unit']        = get_unit_data($value, $unit[$key]);
//         $filterUnit         = array_merge(...array_filter($arr['unit'], function($row) use($qty){ if($row['is_selected'] == 'selected'){ return $row; } }));
//         $nutrientsMerge     = array_merge_recursive($nutrientsMerge, $filterUnit['nutrients']);
//         $dat[] = $arr;
//     }
//     foreach($nutrientsMerge as $key => $value){ $nutrientsMerge[$key] =  (is_array($value)) ? (array_sum($value) * array_sum($qty)) : ($value * array_sum($qty)); }
//     //   $results['ingredients'] = $dat;
//         $results = $nutrientsMerge;
//     }
//   if(!empty($results)){
//     return $results;
//   }else{
//     return 0;
//       }
//     }




function getnutrientsbyid($id){
//     ini_set('display_errors', 1);
// ini_set('display_startup_errors', 1);
// error_reporting(E_ALL);
      global $wpdb;
    $args = array(
      'p' => $id,
      'post_type' => 'recipe',
    );
    if ( ! $post = get_post( $id ) ) {
      return new WP_Error( 'invalid_id', 'Please define a valid post ID.' );
    }
      $query = new WP_Query( $args ); 
      $posts = $query->get_posts();
    foreach( $posts as $post ) {
        $product_id = ($post->product_info)?json_decode($post->product_info):array();
        $qty        = ($post->quantity_info)?json_decode($post->quantity_info):array();
        $unit       = ($post->unit_info)?json_decode($post->unit_info):array();
        $nutrientsMerge  = array();
        
    foreach($product_id as $key => $value){
        $query  = "select food_description from wp_standard_nutrients_wpg where food_id = '{$value}'";
        $produc_name = $wpdb->get_var($query);
        $arr['product']     = array('id' => $value, 'text' => $produc_name);
        $arr['qty']         = $qty[$key];
        $arr['unit']        = get_unit_data($value, $unit[$key]);
        $quantity           = $arr['qty'];
        $selectedUnit       = $unit[$key];
        $filterUnit         = array_merge(...array_filter(array_map(function($row) use($quantity, $selectedUnit){ 
            if($row['is_selected'] == 'selected'){
                foreach($row['nutrients'] as $k => $v){
                    $row['nutrients'][$k] = ($selectedUnit == 'pergram')?($v * $quantity/100) : $v * $quantity;
                }
                return $row;
            }
        }, $arr['unit'])));
        
        $nutrientsMerge     = array_merge_recursive($nutrientsMerge, $filterUnit['nutrients']);
        $dat[] = $arr;
    }
        foreach($nutrientsMerge as $key => $value){ $nutrientsMerge[$key] =  (is_array($value)) ? array_sum($value):$value; }
        $results = $nutrientsMerge;
    }
  if(!empty($results)){
    return $results;
  }else{
    return 0;
      }
    }
    
    function getownnutrients($id){
//     ini_set('display_errors', 1);
// ini_set('display_startup_errors', 1);
// error_reporting(E_ALL);
      global $wpdb;
    $args = array(
      'p' => $id,
      'post_type' => 'recipe',
    );
    if ( ! $post = get_post( $id ) ) {
      return new WP_Error( 'invalid_id', 'Please define a valid post ID.' );
    }
      $query = new WP_Query( $args ); 
      $posts = $query->get_posts();
    foreach( $posts as $post ) {
        $product_id = ($post->product_info)?json_decode($post->product_info):array();
        $qty        = ($post->quantity_info)?json_decode($post->quantity_info):array();
        $unit       = ($post->unit_info)?json_decode($post->unit_info):array();
        $nutrientsMerge  = array();
        
    foreach($product_id as $key => $value){
        $query  = "select food_description from wp_standard_nutrients_wpg where food_id = '{$value}'";
        $produc_name = $wpdb->get_var($query);
        $arr['product']     = array('id' => $value, 'text' => $produc_name);
        $arr['qty']         = $qty[$key];
        $arr['unit']        = get_wpcunit($value, $unit[$key]);
        $quantity           = $arr['qty'];
        $selectedUnit       = $unit[$key];
        $filterUnit         = array_merge(...array_filter(array_map(function($row) use($quantity, $selectedUnit){ 
                  if($row['is_selected'] == ''){
                foreach($row['nutrients'] as $k => $v){
                    $row['nutrients'][$k] = ($selectedUnit == 'pergram')?($v * $quantity/100) : $v * $quantity;
                }
                return $row;
            }
        }, $arr['unit'])));
        
        $nutrientsMerge     = array_merge_recursive($nutrientsMerge, $filterUnit['nutrients']);
        $dat[] = $arr;
    }
        foreach($nutrientsMerge as $key => $value){ $nutrientsMerge[$key] =  (is_array($value)) ? array_sum($value):$value; }
        $results = $nutrientsMerge;
    }
  if(!empty($results)){
    return $results;
  }else{
    return 0;
      }
    }

function get_wpcunit($param,  $isSelected = ''){
    global $wpdb;
    $result = [];
        
        $sql1 = "select  `water`, `energy`, `total_protein`, `total_fat`, `total_carbohydrate`,`total_dietary_fiber`, `insoluble_dietary_fiber`, `soluble_dietary_fiber`, `calcium`, `iron`, `magnesium`, `phosphorus`, `potassium`, `sodium`, 
        `zinc`, `copper`, `manganese`, `selenium`, `vitamin_C_ascorbic_acid`, `thiamin_vitamin_B1`, `riboflavin_vitamin_B2`, `pantothenic_acid`, `vitamin_B6_pyridoxine_pyridoxyl_pyridoxamine`, `dietary_folate_Equivalents`, `vitamin_B12_cobalamin`, `vitamin_D_calciferol`, `vitamin_E_total_alpha_tocopherol`, `vitamin_K_phylloquinone`, `chlorine`, `total_saturated_fatty_acids`, `total_monounsaturated_fatty_acids`, 
        `total_polyunsaturated_fatty_acids`, `total_frans_fatty_acids_trans`, `cholesterol`, `added_sugars_by_total_sugars`, `total_sugars`, `omega_3_fatty_acids`, 
         `total_vitamin_A_activity_retinol_activity_equivalents`, `niacin_equivalents`  from wp_standard_nutrients_wpcps  WHERE food_id = $param";
       
        $wpcps['nutrients'] = $wpdb->get_row($sql1, ARRAY_A);
        array_push($result, $wpcps);
    
    return $result;
}

function getselectedunit($post_id){
 
    global $wpdb;
 $post = get_post($post_id);
        $product_id = ($post->product_info)?json_decode($post->product_info):array();
        $qty        = ($post->quantity_info)?json_decode($post->quantity_info):array();
        $unit       = ($post->unit_info)?json_decode($post->unit_info):array();
        $nutrientsMerge  = array();
      
            foreach($product_id as $key => $value){
        $query  = "select food_description from wp_standard_nutrients_wpg where food_id = '{$value}'";
        $produc_name = $wpdb->get_var($query);
        $arr['product']     = array('id' => $value, 'text' => $produc_name);
        $arr['qty']         = $qty[$key];
        $arr['unit']        = get_unit_data($value, $unit[$key]);
                $filterUnit         = array_merge(...array_filter(array_map(function($row) use($quantity, $selectedUnit){ 
                  if($row['is_selected'] == 'selected'){
                foreach($row['energy'] as $k => $v){
                    $row['energy'][$k] =  $v * $quantity;
                }
                return $row;
            }
        }, $arr['unit'])));
        $dat[] = $arr;
     print_r($arr['unit']);
     die;
       $results['ingredients'] = $dat;
        // $results['total_nutrient'] = $this->getownnutrients($param['id']);
      $results['total_calories'] = $post->energy_content_total_calories;
      $results['calories_per_oz'] = $post->energy_content_nutrients_per_oz;

    }
  if(!empty($results)){
    return $results;
  }else{
    return 0;
      }
    }



}


$serverApi = new CRC_REST_API();
$serverApi->init();
add_filter('jwt_auth_token_before_dispatch',array($serverApi,'jwt_auth'),10,2);

function uploadImage( $base64_img, $title ) {
	$upload_dir  = wp_upload_dir();
	$upload_path = str_replace( '/', DIRECTORY_SEPARATOR, $upload_dir['path'] ) . DIRECTORY_SEPARATOR;
	$img             = str_replace( 'data:image/jpeg;base64,', '', $base64_img );
	$img             = str_replace( ' ', '+', $img );
	$decoded         = base64_decode( $img );
	$filename        = $title . '.jpeg';
	$file_type       = 'image/jpeg';
	$hashed_filename = md5( $filename . microtime() ) . '_' . $filename;
	// Save the image in the uploads directory.
	$upload_file = file_put_contents( $upload_path . $hashed_filename, $decoded );
	$attachment = array(
		'post_mime_type' => $file_type,
		'post_title'     => preg_replace( '/\.[^.]+$/', '', basename( $hashed_filename ) ),
		'post_content'   => '',
		'post_status'    => 'inherit',
		'guid'           => $upload_dir['url'] . '/' . basename( $hashed_filename )
	);
  $attach_id = wp_insert_attachment( $attachment, $upload_dir['path'] . '/' . $hashed_filename );
	return $attach_id;
}

function acf_get_field_key( $field_name, $post_id ) {
	global $wpdb;
	$acf_fields = $wpdb->get_results( $wpdb->prepare( "SELECT ID,post_parent,post_name FROM $wpdb->posts WHERE post_excerpt=%s AND post_type=%s" , $field_name , 'acf-field' ) );
	// get all fields with that name.
	switch ( count( $acf_fields ) ) {
		case 0: // no such field
			return false;
		case 1: // just one result. 
			return $acf_fields[0]->post_name;
	}
	// result is ambiguous
	// get IDs of all field groups for this post
	$field_groups_ids = array();
	$field_groups = acf_get_field_groups( array(
		'post_id' => $post_id,
	) );
	foreach ( $field_groups as $field_group )
		$field_groups_ids[] = $field_group['ID'];
	
	// Check if field is part of one of the field groups
	// Return the first one.
	foreach ( $acf_fields as $acf_field ) {
		if ( in_array($acf_field->post_parent,$field_groups_ids) )
			return $acf_field->post_name;
	}
	return false;
}
##################################################################################

// Custom File Added
include_once(plugin_dir_path(__FILE__).'custom-settings.php');