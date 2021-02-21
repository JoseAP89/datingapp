import { Component, OnInit, Input, Output, EventEmitter } from '@angular/core';
import { AccountService } from '../_services/account.service';
import { ToastrService } from 'ngx-toastr';

@Component({
    selector: 'app-register',
    templateUrl: './register.component.html',
    styleUrls: ['./register.component.css']
})
export class RegisterComponent implements OnInit {
    //output property for child to parent communication, we are emitting events
    @Output() cancelRegister = new EventEmitter();
    model: any = {};

    constructor(private accountService: AccountService, private toastr: ToastrService) { }

    ngOnInit(): void {
    }

    register(){
        this.accountService.register(this.model).subscribe(response =>{
            console.log(response);
            this.cancel();
        }, error => {
            console.log(error);
            this.toastr.error(error.error);
        })
    }

    cancel(){
       this.cancelRegister.emit(false); 
    }
}
