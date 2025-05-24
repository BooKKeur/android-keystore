use jni::{
    AttachGuard,
    objects::{JClass, JObject, JString, JValue},
    strings::JNIString,
};

pub mod keygen_parameter_spec;
pub mod keypair;
pub mod keypair_generator;
pub mod utils;
pub use keypair::PrivateKey;
pub use utils::with_jni_env;

pub trait Object<'a> {
    fn class(env: &mut AttachGuard<'a>) -> JClass<'a>;

    fn l(&self) -> &JObject<'a>;

    fn to_jstring(&self, env: &mut AttachGuard<'a>) -> jni::errors::Result<JString<'a>> {
        Ok(env
            .call_method(self.l(), "toString", "()Ljava/lang/String;", &[])?
            .l()?
            .into())
    }

    fn to_jni_string(&self, env: &mut AttachGuard<'a>) -> jni::errors::Result<JNIString> {
        let jstring = unsafe { JString::from_raw(**self.to_jstring(env)?) };
        Ok(env.get_string(jstring.as_ref())?.to_owned())
    }
}

pub struct AndroidKeyStore<'a> {
    inner: JObject<'a>,
}

impl<'a> AndroidKeyStore<'a> {
    pub fn get_instance(env: &mut AttachGuard<'a>) -> AndroidKeyStore<'a> {
        let keystore_class = env
            .find_class("java/security/KeyStore")
            .expect("Failed to find KeyStore class");
        let android_key_store_string = env
            .new_string("AndroidKeyStore")
            .expect("Failed to create AndroidKeyStore string");

        AndroidKeyStore {
            inner: env
                .call_static_method(
                    keystore_class,
                    "getInstance",
                    "(Ljava/lang/String;)Ljava/security/KeyStore;",
                    &[JValue::Object(&android_key_store_string)],
                )
                .expect("Failed to call getInstance() method")
                .l()
                .expect("Failed to get JObject()"),
        }
    }

    pub fn load(&self, env: &mut AttachGuard<'a>) {
        env.call_method(
            &self.inner,
            "load",
            "(Ljava/security/KeyStore$LoadStoreParameter;)V",
            &[JValue::Object(&JObject::null())],
        )
        .expect("Failed to call load() method");
    }

    pub fn aliases(&self, env: &mut AttachGuard<'a>) -> Vec<String> {
        let mut res = vec![];
        let aliases = env
            .call_method(&self.inner, "aliases", "()Ljava/util/Enumeration;", &[])
            .expect("Failed to call aliases() method")
            .l()
            .expect("Failed to get Enumeration");

        while env
            .call_method(&aliases, "hasMoreElements", "()Z", &[])
            .expect("Failed to call hasMoreElements() method")
            .z()
            .expect("Failed to get boolean")
        {
            let string_object: JString<'_> = env
                .call_method(&aliases, "nextElement", "()Ljava/lang/Object;", &[])
                .expect("Failed to call nextElement() method")
                .l()
                .expect("Failed to get Object")
                .into();
            res.push(
                env.get_string(&string_object)
                    .expect("Failed to get string")
                    .to_str()
                    .expect("Failed to get str")
                    .into(),
            );
        }

        res
    }

    pub fn get_entry<S>(&self, alias: S, env: &mut AttachGuard<'a>) -> PrivateKeyEntry<'a>
    where
        S: Into<JNIString>,
    {
        let alias = env.new_string(alias).unwrap();

        let entry = env.call_method(&self.inner, "getEntry", "(Ljava/lang/String;Ljava/security/KeyStore$ProtectionParameter;)Ljava/security/KeyStore$Entry;", &[JValue::Object(&alias), JValue::Object(&JObject::null())])
        // .expect("Failed to get entry").l().expect("Failed to get JObject")
        ;

        if env.exception_check().expect("Failed to check exception") {
            env.exception_describe()
                .expect("Failed to describe exception");
        }
        let entry = entry
            .expect("Failed to get entry")
            .l()
            .expect("Failed to get JObject");

        if !env
            .is_instance_of(&entry, "java/security/KeyStore$PrivateKeyEntry")
            .expect("Failed to call instanceof")
        {
            todo!("Handle other entry types")
        }
        PrivateKeyEntry { inner: entry }
    }
}

impl<'a> Object<'a> for AndroidKeyStore<'a> {
    fn class(env: &mut AttachGuard<'a>) -> JClass<'a> {
        env.find_class("android/security/keystore/AndroidKeyStore")
            .expect("Failed to find AndroidKeyStore class")
    }

    fn l(&self) -> &JObject<'a> {
        &self.inner
    }
}

pub struct PrivateKeyEntry<'a> {
    inner: JObject<'a>,
}

impl<'a> PrivateKeyEntry<'a> {
    pub fn get_private_key(&self, env: &mut AttachGuard<'a>) -> PrivateKey<'a> {
        PrivateKey {
            inner: env
                .call_method(
                    &self.inner,
                    "getPrivateKey",
                    "()Ljava/security/PrivateKey;",
                    &[],
                )
                .expect("Failed to call getPrivateKey() method")
                .l()
                .expect("Failed to get JObject"),
        }
    }
}

impl<'a> Object<'a> for PrivateKeyEntry<'a> {
    fn class(env: &mut AttachGuard<'a>) -> JClass<'a> {
        env.find_class("java/security/KeyStore$PrivateKeyEntry")
            .expect("Failed to find PrivateKeyEntry class")
    }

    fn l(&self) -> &JObject<'a> {
        &self.inner
    }
}
