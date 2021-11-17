<?php

namespace App\Http\Controllers\API;

use App\Models\Logs;
use App\Models\User;
use App\Models\Enrollment;

use Illuminate\Support\Str;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class EnrollmentController extends Controller {

    public $successStatus = 200;

    public function login() {
        if (Auth::attempt(['username' => request('username'), 'password' => request('password')])) {
            $user = Auth::user();

            $success['token'] = Str::random(64);
            $success['username'] = $user->username;
            $success['id'] = $user->id;
            $success['name'] = $user->name;

            // SAVE TOKEN
            $user->remember_token = $success['token'];
            $user->save();
           

            // create an instance of logs model
            
            $logs = new Logs();

            $logs->userid = $user->id;
            $logs->log = "Login";
            $logs->logdetails = "User $user->username has logged in successfully into my system.";
            $logs->logtype = "API Login";
            $logs->save();

            return response()->json($success, $this->successStatus);
        } else {
            return response()->json(['response' => 'User not found'], 404);
        }
    }

    public function register(Request $request) {
        $validator = Validator::make($request->all(), [
            'name' => 'required',
            'username' => 'required',
            'email' => 'required|email',
            'password' => 'required',
        ]);

        if ($validator->fails()) {
            return response()->json(['response' => $validator->errors()], 401);
        } else {
            $input = $request->all();

            if (User::where('email', $input['email'])->exists()) {
                return response()->json(['response' => 'Email already exists'], 401);
            } elseif(User::where('username', $input['username'])->exists()) {
                return response()->json(['response' => 'Username already exists'], 401);
            } else {
                $input['password'] = bcrypt($input['password']);
                $user = User::create($input);

                $success['token'] = Str::random(64);
                $success['username'] = $user->username;
                $success['id'] = $user->id;
                $success['name'] = $user->name;

                return response()->json($success, $this->successStatus);
            }
        }
    }

    public function resetPassword(Request $request) {
        $user = User::where('email', $request['email'])->first();

        if ($user != null) {
            $user->password = bcrypt($request['password']);
            $user->save();

            return response()->json(['response' => 'User has successfully resetted his/her password'], $this->successStatus);
        } else {
            return response()->json(['response' => 'User not found'], 404);
        }
    }
    
    public function getAllEnrollment(Request $request) {
        $token = $request['t']; // t = token
        $userid = $request['u']; // u = userid

        $user = User::where('id', $userid)->where('remember_token', $token)->first();

        if ($user != null) {
            $enrollment = Enrollment::all();

            return response()->json($enrollment, $this->successStatus);
        } else {
            return response()->json(['response' => 'Bad Call'], 501);
        }        
    }  
    
    public function getEnrollment(Request $request) {
        $id = $request['pid']; // pid = enrollmentid
        $token = $request['t']; // t = token
        $userid = $request['u']; // u = userid

        $user = User::where('id', $userid)->where('remember_token', $token)->first();

        if ($user != null) {
            $enrollment= Enrollment::where('id', $id)->first();

            if ($enrollment!= null) {
                return response()->json($enrollment, $this->successStatus);
            } else {
                return response()->json(['response' => 'Enrollment not found!'], 404);
            }            
        } else {
            return response()->json(['response' => 'Bad Call'], 501);
        }  
    }

    public function searchEnrollment(Request $request) {
        $params = $request['p']; // p = params
        $token = $request['t']; // t = token
        $userid = $request['u']; // u = userid

        $user = User::where('id', $userid)->where('remember_token', $token)->first();

        if ($user != null) {
            $enrollment= Enrollment::where('religion', 'LIKE', '%' . $params . '%')
                ->orWhere('citizenship', 'LIKE', '%' . $params . '%')
                ->get();
            
            if ($enrollment!= null) {
                return response()->json($enrollment, $this->successStatus);
            } else {
                return response()->json(['response' => 'enrollmentnot found!'], 404);
            }            
        } else {
            return response()->json(['response' => 'Bad Call'], 501);
        }  
    }
}

?>