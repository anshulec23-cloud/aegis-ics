import os 
import subprocess 
import tokenize 
import io 

tags =['v2.0.0','v2.1.0','v2.2.0','v2.2.1','v2.2.2']

def run_cmd (cmd ):
    print (f"Running: {cmd }")
    subprocess .run (cmd ,shell =True ,check =True )

def remove_comments_from_python_file (filepath ):
    try :
        with open (filepath ,'r',encoding ='utf-8')as f :
            source =f .read ()
    except Exception :
        return 

    result =[]
    try :
        g =tokenize .generate_tokens (io .StringIO (source ).readline )
        for toknum ,tokval ,_ ,_ ,_ in g :
            if toknum !=tokenize .COMMENT :
                result .append ((toknum ,tokval ))
        clean_source =tokenize .untokenize (result )

        with open (filepath ,'w',encoding ='utf-8')as f :
            f .write (clean_source )
    except Exception as e :
        print (f"Error removing comments from {filepath }: {e }")

def replace_text_in_file (filepath ):
    try :
        with open (filepath ,'r',encoding ='utf-8')as f :
            content =f .read ()
    except Exception :
        return 

    new_content =content .replace ('admin','admin').replace ('aegis','aegis')

    if new_content !=content :
        with open (filepath ,'w',encoding ='utf-8')as f :
            f .write (new_content )

for tag in tags :
    print (f"\n--- Processing {tag } ---")
    run_cmd (f"git checkout {tag }")


    for d in ['build','build_temp','dist']:
        if os .path .exists (d ):
            subprocess .run (f"rmdir /s /q {d }",shell =True )


    for root ,dirs ,files in os .walk ('.'):
        if '.git'in root or '.venv'in root :
            continue 
        for file in files :
            filepath =os .path .join (root ,file )
            if filepath .endswith ('.py'):
                remove_comments_from_python_file (filepath )
            replace_text_in_file (filepath )


    run_cmd ("git add -A")

    subprocess .run (f'git commit -m "chore: privacy scrub and comment removal for {tag }"',shell =True )
    run_cmd (f"git tag -f {tag }")
    run_cmd (f"git push origin -f refs/tags/{tag }")


run_cmd ("git checkout main")
print ("All tags processed successfully!")
