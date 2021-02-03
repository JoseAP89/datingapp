import { Component, OnInit } from '@angular/core';
//import { userInfo } from 'os';
import { AccountService } from '../_services/account.service';

@Component({
    selector: 'app-nav',
    templateUrl: './nav.component.html',
    styleUrls: ['./nav.component.css']
})
export class NavComponent implements OnInit {
    model: any = {};

    constructor(public accountService: AccountService) { 
    }

    ngOnInit(): void {
    }

    login() {
        this.accountService.login(this.model).subscribe( resp => {
            console.log(resp);
        }, err => {
            console.log(err);
        });
    }

    logout() {
        this.accountService.logout();
    }

}
