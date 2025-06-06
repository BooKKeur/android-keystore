use jni::{AttachGuard, strings::JNIString};

use crate::{
    JClass, JObject, JObjectWrapper, JValue, Object, keygen_parameter_spec::KeyGenParameterSpec,
    keypair::KeyPair,
};

pub enum Algorithm {
    DH,
    DSA,
    #[cfg(feature = "api_level_11")]
    EC,
    RSA,
    #[cfg(feature = "api_level_33")]
    XDH,
}

impl From<&Algorithm> for JNIString {
    fn from(val: &Algorithm) -> Self {
        match val {
            Algorithm::DH => "DH".into(),
            Algorithm::DSA => "DSA".into(),
            #[cfg(feature = "api_level_11")]
            Algorithm::EC => "EC".into(),
            Algorithm::RSA => "RSA".into(),
            #[cfg(feature = "api_level_33")]
            Algorithm::XDH => "XDH".into(),
        }
    }
}

pub enum Provider {
    AndroidKeyStore,
    //TODO: Add more providers
}

impl From<&Provider> for JNIString {
    fn from(val: &Provider) -> Self {
        match val {
            Provider::AndroidKeyStore => "AndroidKeyStore".into(),
        }
    }
}

#[derive(Debug)]
pub enum Exception {
    NoSuchAlgorithmException(jni::errors::Error),
    InvalidAlgorithmParameterException(jni::errors::Error),
}

/// A wrapper around a JObject representing a KeyPairGenerator instance
/// KeyPairGenerator being a singleton, it must be created using the `get_instance()` method
/// The instance obtained using `get_instance()` can then be used to generate a keypair
#[derive(Debug, Clone, Copy)]
pub struct KeyPairGenerator<'a>(JObjectWrapper<'a>);

impl<'a> From<JObject<'a>> for KeyPairGenerator<'a> {
    fn from(value: JObject<'a>) -> Self {
        Self(value.into())
    }
}

impl<'a> KeyPairGenerator<'a> {
    pub fn get_instance(
        algorithm: Algorithm,
        provider: Provider,
        env: &mut AttachGuard<'a>,
    ) -> Result<Self, Exception> {
        let keypair_generator_class = env
            .find_class("java/security/KeyPairGenerator")
            .expect("Failed to find KeyPairGenerator class");

        let algorithm = &env
            .new_string(&algorithm)
            .expect("Cannot create string for algorithm");

        let provider = &env
            .new_string(&provider)
            .expect("Cannot create string for provider");

        Ok(env
            .call_static_method(
                keypair_generator_class,
                "getInstance",
                "(Ljava/lang/String;Ljava/lang/String;)Ljava/security/KeyPairGenerator;",
                &[JValue::Object(algorithm), JValue::Object(provider)],
            )
            .map_err(Exception::NoSuchAlgorithmException)?
            .l()
            .expect("Failed to get JObject")
            .into())
    }

    pub fn initialize(
        self,
        keygen_parameter_spec: KeyGenParameterSpec<'a>,
        env: &mut AttachGuard<'a>,
    ) -> Result<(), Exception> {
        let res = env.call_method(
            self.l(),
            "initialize",
            "(Ljava/security/spec/AlgorithmParameterSpec;)V",
            &[JValue::Object(&keygen_parameter_spec.l())],
        )
        // .map_err(Exception::InvalidAlgorithmParameterException)?
        ;

        if env.exception_check().unwrap() {
            env.exception_describe().unwrap();
            res.map_err(Exception::InvalidAlgorithmParameterException)?;
        }

        Ok(())
    }

    pub fn generate_keypair(self, env: &mut AttachGuard<'a>) -> KeyPair<'a> {
        env.call_method(
            self.l(),
            "generateKeyPair",
            "()Ljava/security/KeyPair;",
            &[],
        )
        .expect("Failed to call generateKeyPair")
        .l()
        .expect("Failed to get JObject")
        .into()
    }
}

impl<'a> Object<'a> for KeyPairGenerator<'a> {
    fn class(env: &mut AttachGuard<'a>) -> JClass<'a> {
        env.find_class("java/security/KeyPairGenerator")
            .expect("Failed to find KeyPairGenerator class")
    }

    fn l(self) -> JObject<'a> {
        self.0.l()
    }
}
