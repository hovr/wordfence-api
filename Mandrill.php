<?php

class Mandrill_Error extends Exception {}
class Mandrill_HttpError extends Mandrill_Error {}
class Mandrill_ValidationError extends Mandrill_Error {}
class Mandrill_Invalid_Key extends Mandrill_Error {}
class Mandrill_PaymentRequired extends Mandrill_Error {}
class Mandrill_Unknown_Subaccount extends Mandrill_Error {}
class Mandrill_Unknown_Template extends Mandrill_Error {}
class Mandrill_ServiceUnavailable extends Mandrill_Error {}
class Mandrill_Unknown_Message extends Mandrill_Error {}
class Mandrill_Invalid_Tag_Name extends Mandrill_Error {}
class Mandrill_Invalid_Reject extends Mandrill_Error {}
class Mandrill_Unknown_Sender extends Mandrill_Error {}
class Mandrill_Unknown_Url extends Mandrill_Error {}
class Mandrill_Unknown_TrackingDomain extends Mandrill_Error {}
class Mandrill_Invalid_Template extends Mandrill_Error {}
class Mandrill_Unknown_Webhook extends Mandrill_Error {}
class Mandrill_Unknown_InboundDomain extends Mandrill_Error {}
class Mandrill_Unknown_InboundRoute extends Mandrill_Error {}
class Mandrill_Unknown_Export extends Mandrill_Error {}
class Mandrill_IP_ProvisionLimit extends Mandrill_Error {}
class Mandrill_Unknown_Pool extends Mandrill_Error {}
class Mandrill_NoSendingHistory extends Mandrill_Error {}
class Mandrill_PoorReputation extends Mandrill_Error {}
class Mandrill_Unknown_IP extends Mandrill_Error {}
class Mandrill_Invalid_EmptyDefaultPool extends Mandrill_Error {}
class Mandrill_Invalid_DeleteDefaultPool extends Mandrill_Error {}
class Mandrill_Invalid_DeleteNonEmptyPool extends Mandrill_Error {}
class Mandrill_Invalid_CustomDNS extends Mandrill_Error {}
class Mandrill_Invalid_CustomDNSPending extends Mandrill_Error {}
class Mandrill_Metadata_FieldLimit extends Mandrill_Error {}
class Mandrill_Unknown_MetadataField extends Mandrill_Error {}

class Mandrill {

	public $apikey;
	public $root = 'https://mandrillapp.com/api/1.0/';
	public $debug = false;
	public $messages;
	public $templates;
	public $allowlists;
	public $whitelists;

	public static $error_map = array(
		'ValidationError' => 'Mandrill_ValidationError',
		'Invalid_Key' => 'Mandrill_Invalid_Key',
		'PaymentRequired' => 'Mandrill_PaymentRequired',
		'Unknown_Subaccount' => 'Mandrill_Unknown_Subaccount',
		'Unknown_Template' => 'Mandrill_Unknown_Template',
		'ServiceUnavailable' => 'Mandrill_ServiceUnavailable',
		'Unknown_Message' => 'Mandrill_Unknown_Message',
		'Invalid_Tag_Name' => 'Mandrill_Invalid_Tag_Name',
		'Invalid_Reject' => 'Mandrill_Invalid_Reject',
		'Unknown_Sender' => 'Mandrill_Unknown_Sender',
		'Unknown_Url' => 'Mandrill_Unknown_Url',
		'Unknown_TrackingDomain' => 'Mandrill_Unknown_TrackingDomain',
		'Invalid_Template' => 'Mandrill_Invalid_Template',
		'Unknown_Webhook' => 'Mandrill_Unknown_Webhook',
		'Unknown_InboundDomain' => 'Mandrill_Unknown_InboundDomain',
		'Unknown_InboundRoute' => 'Mandrill_Unknown_InboundRoute',
		'Unknown_Export' => 'Mandrill_Unknown_Export',
		'IP_ProvisionLimit' => 'Mandrill_IP_ProvisionLimit',
		'Unknown_Pool' => 'Mandrill_Unknown_Pool',
		'NoSendingHistory' => 'Mandrill_NoSendingHistory',
		'PoorReputation' => 'Mandrill_PoorReputation',
		'Unknown_IP' => 'Mandrill_Unknown_IP',
		'Invalid_EmptyDefaultPool' => 'Mandrill_Invalid_EmptyDefaultPool',
		'Invalid_DeleteDefaultPool' => 'Mandrill_Invalid_DeleteDefaultPool',
		'Invalid_DeleteNonEmptyPool' => 'Mandrill_Invalid_DeleteNonEmptyPool',
		'Invalid_CustomDNS' => 'Mandrill_Invalid_CustomDNS',
		'Invalid_CustomDNSPending' => 'Mandrill_Invalid_CustomDNSPending',
		'Metadata_FieldLimit' => 'Mandrill_Metadata_FieldLimit',
		'Unknown_MetadataField' => 'Mandrill_Unknown_MetadataField',
	);

	public function __construct ( $apikey = null ) {

		if ( !$apikey ) $apikey = getenv( 'MANDRILL_APIKEY' );
		if ( !$apikey ) $apikey = $this -> readConfigs();
		if ( !$apikey ) throw new Mandrill_Error( 'You must provide a Mandrill API key' );

		$this -> apikey = $apikey;
		$this -> root = rtrim( $this -> root, '/' ) . '/';
		$this -> messages = new Mandrill_Messages( $this );
		$this -> templates = new Mandrill_Templates( $this );
		$this -> allowlists = new Mandrill_Allowlists( $this );
		$this -> whitelists = $this -> allowlists;

	}

	public function call ( $url, $params = array() ) {

		if ( !function_exists( 'curl_init' ) ) {

			throw new Mandrill_HttpError( 'The PHP curl extension is required to call the Mandrill API.' );

		}

		$params['key'] = $this -> apikey;
		$payload = json_encode( $params );

		if ( $payload === false ) {

			throw new Mandrill_Error( 'Unable to encode Mandrill API request payload.' );

		}

		$ch = curl_init();

		curl_setopt( $ch, CURLOPT_URL, $this -> root . $url . '.json' );
		curl_setopt( $ch, CURLOPT_POST, true );
		curl_setopt( $ch, CURLOPT_POSTFIELDS, $payload );
		curl_setopt( $ch, CURLOPT_HTTPHEADER, array( 'Content-Type: application/json' ) );
		curl_setopt( $ch, CURLOPT_USERAGENT, 'HFE-Mandrill-Curl/1.0' );
		curl_setopt( $ch, CURLOPT_FOLLOWLOCATION, true );
		curl_setopt( $ch, CURLOPT_HEADER, false );
		curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );
		curl_setopt( $ch, CURLOPT_CONNECTTIMEOUT, 30 );
		curl_setopt( $ch, CURLOPT_TIMEOUT, 600 );
		curl_setopt( $ch, CURLOPT_VERBOSE, $this -> debug );

		$this -> log( 'Call to ' . $this -> root . $url . '.json: ' . $payload );

		$response = curl_exec( $ch );
		$curlError = curl_error( $ch );
		$info = curl_getinfo( $ch );
		curl_close( $ch );

		if ( $curlError ) {

			throw new Mandrill_HttpError( "API call to $url failed: " . $curlError );

		}

		$this -> log( 'Got response: ' . $response );

		$result = json_decode( $response, true );

		if ( $result === null && json_last_error() !== JSON_ERROR_NONE ) {

			throw new Mandrill_Error( 'Unable to decode the JSON response from the Mandrill API: ' . $response );

		}

		if ( !empty( $info['http_code'] ) && floor( $info['http_code'] / 100 ) >= 4 ) {

			throw $this -> castError( $result );

		}

		return $result;

	}

	public function readConfigs () {

		foreach ( array( '~/.mandrill.key', '/etc/mandrill.key' ) as $path ) {

			if ( file_exists( $path ) ) {

				$apikey = trim( file_get_contents( $path ) );
				if ( $apikey ) return $apikey;

			}

		}

		return false;

	}

	public function castError ( $result ) {

		if ( empty( $result ) || empty( $result['status'] ) || $result['status'] !== 'error' || empty( $result['name'] ) ) {

			return new Mandrill_Error( 'Unexpected Mandrill API error: ' . json_encode( $result ) );

		}

		$class = !empty( self::$error_map[$result['name']] ) ? self::$error_map[$result['name']] : 'Mandrill_Error';
		$message = !empty( $result['message'] ) ? $result['message'] : 'Mandrill API error.';
		$code = !empty( $result['code'] ) ? $result['code'] : 0;

		return new $class( $message, $code );

	}

	public function log ( $msg ) {

		if ( $this -> debug ) error_log( $msg );

	}

}

class Mandrill_Messages {

	private $master;

	public function __construct ( Mandrill $master ) {

		$this -> master = $master;

	}

	public function send ( $message, $async = false, $ip_pool = null, $send_at = null ) {

		return $this -> master -> call( 'messages/send', array(
			'message' => $message,
			'async' => $async,
			'ip_pool' => $ip_pool,
			'send_at' => $send_at,
		) );

	}

	public function sendTemplate ( $template_name, $template_content, $message, $async = false, $ip_pool = null, $send_at = null ) {

		return $this -> master -> call( 'messages/send-template', array(
			'template_name' => $template_name,
			'template_content' => $template_content,
			'message' => $message,
			'async' => $async,
			'ip_pool' => $ip_pool,
			'send_at' => $send_at,
		) );

	}

	public function info ( $id ) {

		return $this -> master -> call( 'messages/info', array( 'id' => $id ) );

	}

}

class Mandrill_Templates {

	private $master;

	public function __construct ( Mandrill $master ) {

		$this -> master = $master;

	}

	public function getList ( $label = null ) {

		return $this -> master -> call( 'templates/list', array( 'label' => $label ) );

	}

	public function info ( $name ) {

		return $this -> master -> call( 'templates/info', array( 'name' => $name ) );

	}

	public function update ( $name, $from_email = null, $from_name = null, $subject = null, $code = null, $text = null, $publish = true, $labels = null ) {

		return $this -> master -> call( 'templates/update', array(
			'name' => $name,
			'from_email' => $from_email,
			'from_name' => $from_name,
			'subject' => $subject,
			'code' => $code,
			'text' => $text,
			'publish' => $publish,
			'labels' => $labels,
		) );

	}

}

class Mandrill_Allowlists {

	private $master;

	public function __construct ( Mandrill $master ) {

		$this -> master = $master;

	}

	public function add ( $email, $comment = null ) {

		return $this -> master -> call( 'allowlists/add', array( 'email' => $email, 'comment' => $comment ) );

	}

	public function getList ( $email = null ) {

		return $this -> master -> call( 'allowlists/list', array( 'email' => $email ) );

	}

	public function delete ( $email ) {

		return $this -> master -> call( 'allowlists/delete', array( 'email' => $email ) );

	}

}
