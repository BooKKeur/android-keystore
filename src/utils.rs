use jni::{
    AttachGuard, JavaVM,
    objects::{JObjectArray, JString},
    strings::JNIString,
    sys::_jobject,
};

use crate::JObject;

pub fn with_jni_env<Func, Ret>(f: Func) -> Ret
where
    Func: FnOnce(AttachGuard<'_>, *mut _jobject) -> Ret,
{
    let ctx = ndk_context::android_context();

    // SAFETY: We assume that the pointer returned by android_context() is valid
    let vm = unsafe { JavaVM::from_raw(ctx.vm().cast()).expect("Failed to get JavaVM") };
    let env = vm.attach_current_thread().expect("Failed to attach thread");

    // SAFETY: We assume that the activity pointer is valid
    let activity = unsafe { JObject::from_raw(ctx.context().cast()) };

    f(env, activity.to_owned())
}

pub fn make_string_array<'a, S>(strings: &'a [S], env: &mut AttachGuard<'a>) -> JObjectArray<'a>
where
    &'a S: Into<JNIString>,
{
    let string_class = env
        .find_class("java/lang/String")
        .expect("Cannot find String class");

    let string_array = env
        .new_object_array(strings.len() as i32, &string_class, JObject::null())
        .expect("Cannot create string array object");

    for (i, val) in strings.iter().enumerate() {
        let java_str: JString = env.new_string(val).expect("Cannot create string object");
        env.set_object_array_element(&string_array, i as i32, java_str)
            .expect("Failed to add element to string array");
    }

    string_array
}

pub fn get_internal_directory_path<'a>(
    env: &mut AttachGuard<'a>,
    activity: &JObject<'a>,
) -> String {
    let files_dir_obj = env
        .call_method(activity, "getFilesDir", "()Ljava/io/File;", &[])
        .expect("Failed to call getFilesDir() method")
        .l()
        .expect("Failed to get JObject");

    let path_obj: JString<'a> = env
        .call_method(
            files_dir_obj,
            "getAbsolutePath",
            "()Ljava/lang/String;",
            &[],
        )
        .expect("Failed to call getAbsolutePath() method")
        .l()
        .expect("Failed to get JObject")
        .into();

    env.get_string(&path_obj)
        .expect("Failed to get string")
        .into()
}
