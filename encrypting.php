<p>
	<b>Worst Possible Way of Encrypting (md5):</b><br>
	Hashing <b>password</b><br>
	<?php
		$password = md5('password');
		echo $password;
	?>
</p>

<p>
	<b>Sha256:</b><br>
	Hashing <b>password</b><br>
	<?php
		/* Gen Salt */
		function genSalt()
		{
			$salt = uniqid(rand(), true) . md5(uniqid(rand(), true));
			$salt = hash('sha256', $salt);
			return $salt;
		}
		
		/* Gen Password */
		function genHash($salt, $password)
		{
			/* Hash Password with sha256 */
			$hash = $salt . $password;
			/* ReHash the password */
			for ($i = 0; $i < 100000; $i++)
			{
				$hash = hash('sha256', $hash);
			}
			/* Salt + hash = smart */
			$hash = $salt . $hash;
			return $hash;
		}
		
		$password = genHash(genSalt(), 'password');
		echo $password;
	?>
</p>

<p>
	<b>PBKDF2:</b><br>
	Hashing <b>password</b><br>
	<?php
		/** PBKDF2 Implementation (described in RFC 2898)
		 *  
		 *  @param string p password
		 *  @param string s salt
		 *  @param int c iteration count (use 1000 or higher)
		 *  @param int kl derived key length
		 *  @param string a hash algorithm
		 *
		 *  @return string derived key
		 */
		 
		function pbkdf2($p, $s, $c, $kl, $a = 'sha256')
		{
			$hl = strlen(hash($a, null, true));	# Hash length
			$kb = ceil($kl / $hl);				# Key blocks to comp
			$dk = '';							# Derived key
			
			# Create key
			for ($block = 1; $block <= $kb; $block++)
			{
				# Initial hash for this block
				$ib = $b = hash_hmac($a, $s . pack('N', $block), $p, true);
				
				# Perform block iterations
				for ($i = 1; $i < $c; $i++)
				{
					# XOR each iterate
					$ib ^= ($b = hash_hmac($a, $b, $p, true));
				}
				
				$dk .= $ib; # Append iterated block
			}
			
			# Return derived key of correct length
			return substr($dk, 0, $kl);
		}
		$pass = 'password';
		$salt = 'adfasdfasdfasfasfasfasdf';
		
		$hash = pbkdf2($pass, $salt, 1000, 32);
		echo $hash;
	?>
</p>

<p>
	<b>Bcrypt:</b><br>
	Hashing <b>password</b><br>
	<?php
		/* Bcrypt Example */
		class bcrypt
		{
			private $rounds;
			public function __construct($rounds = 12)
			{
				if(CRYPT_BLOWFISH != 1)
				{
					throw new Exception('Bcrypt is not supported on this server, please see the following to learn more: http://php.net/crypt');
				}
				$this->rounds = $rounds;
			}
			
			/* Gen Salt */
			public function genSalt()
			{
				/* openssl_random_psuedo_bytes(16) Fallback */
				$seed = '';
				for ($i = 0; $i < 16; $i++)
				{
					$seed .= chr(mt_rand(0, 255));
				}
				
				/* GenSalt */
				$salt = substr(strtr(base64_encode($seed), '+', '.'), 0, 22);
				
				/* Return */
				return $salt;
			}
			
			public function genHash($password)
			{
				/* Explain '$2y$' . $this->rounds . '$'
				 *	2a selects bcrypt algorithm
				 *	$this->rounds is the workload factor
				 */
			
				/* GenHash */
				$hash = crypt($password, '$2y$' . $this->rounds . '$' . $this->genSalt());
				
				/* Return */
				return $hash;
			}
			
			/* Verify Password */
			public function verify($password, $existingHash)
			{
				/* Hash new password with old hash */
				$hash = crypt($password, $existingHash);
				
				/* Do Hashes match? */
				if ($hash == $existingHash)
				{
					return true;
				}
				else
				{
					return false;
				}
			}
		}
		
		/* Next the usage */
		/* Start Instance */
		$bcrypt = new bcrypt(12);
		
		/* Two create a Hash */
		echo 'Bcrypt Password: ' . $bcrypt->genHash('password') . '<br>';
		
		/* Two verify a hash */
		$HashFromDB = $bcrypt->genHash('password'); /* This is an example you would draw the hash from your db */
		echo 'Verify Password: ' . $bcrypt->verify('password', $HashFromDB);
	?>
</p>
<p>
</p>

