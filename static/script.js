
document
.getElementById("registerForm")
.addEventListener(
"submit",
async function(event){


    event.preventDefault();



    let formData =
    new FormData(this);



    let messageBox =
    document.getElementById("message");



    messageBox.innerHTML =
    `
    <span class="text-info">
    <i class="fa-solid fa-spinner fa-spin"></i>
    Checking Security...
    </span>
    `;



    try {


        let response =
        await fetch(
            "/register",
            {

                method:"POST",

                body:formData

            }
        );



        let result =
        await response.json();





        if(result.status === "success"){


            messageBox.innerHTML =
            `
            <span class="text-success">

            <i class="fa-solid fa-circle-check"></i>

            ${result.message}

            </span>
            `;


            document
            .getElementById("registerForm")
            .reset();



        }



        else if(result.status === "danger"){


            messageBox.innerHTML =
            `
            <span class="text-danger">

            <i class="fa-solid fa-triangle-exclamation"></i>

            ${result.message}

            </span>
            `;


        }




        else{


            messageBox.innerHTML =
            `
            <span class="text-warning">

            <i class="fa-solid fa-lock"></i>

            ${result.message}

            </span>
            `;


        }



    }


    catch(error){


        messageBox.innerHTML =
        `
        <span class="text-danger">

        Server Connection Error

        </span>
        `;


        console.log(error);


    }


});