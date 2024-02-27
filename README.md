#### Samuel Nwoye - Infrastructure Engineer with Security Skills.
#### How the Site was Created and Deployed
##### creating the site
hugo new site knoxknot.github.io --format yaml  # create a new site
cd knoxknot.github.io # change into the directory
git clone https://github.com/dillonzq/LoveIt themes/LoveIt  # clone a theme
rm -fr themes/LoveIt/{.git,exampleSite,resources}  # personalize the theme

##### describing the project
gh auth login -h github.com -p https -w # authenticate to github
gh auth setup-git # configure git to use gh as credential helper
gh repo create knoxknot.github.io --public --homepage https://github.com/knoxknot --description "Personal Page" # create the remote repository
gh auth status # view authentication status
git init . # initialize git in the current directory
git config --local user.name knoxknot # set git username
git config --local user.email "" # set git usermail
git config --local init.defaultBranch main    # make main branch default
git remote add origin https://github.com/knoxknot/knoxknot.github.io.git # point local to remote
git commit --allow-empty -m "initial commit" # initial empty commit
git push -u origin main # push to remote main
git checkout -b develop

##### developing the site
hugo new --kind writings writings/2023-03-27/'New Writeup.md'  # create an article
hugo server -D --disableFastRender  # view the article
touch .gitignore CNAME README.md   # create and update these files
tee .gitignore <<EOF
/resources
.terraform/
terraform.tfstate
*.tfvars
EOF
tee CNAME <<EOF
samuelnwoye.website
www.samuelnwoye.website
EOF

##### install pre-commit hooks
tee .pre-commit-config.yaml <<EOF
repos:
- repo: https://github.com/zricethezav/gitleaks
  rev: v8.18.1
  hooks:
  - id: gitleaks
EOF # write pre-commit hooks
pre-commit install # install hook at .git/hooks/pre-commit
pre-commit autoupdate # update hook repos to latest version
pre-commit run --all-files # run hooks

git push -u origin develop
git add .
git commit -m "chore: developed initial layout"
git push