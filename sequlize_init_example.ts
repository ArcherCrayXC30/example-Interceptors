import { Sequelize } from 'sequelize';

import IDbInterface from '../types/DInterface';
import { ArticleFactory } from './articles/article';
import { ArticleTagsFactory } from './articles/articlesTags';
import { BriefCaseFactory } from './articles/briefCase';
import { ArticleCategoryFactory } from './articles/categories';
import { CategoryTypesFactory } from './articles/categoryTypes';
import { InvestIdeaFactory } from './articles/investIdea';
import { ArtTagFactory } from './articles/tags';
import { TechAnalysisFactory } from './articles/techAnalysis';
import { ArticleTypeFactory } from './articles/types';
import { CompanyFactory } from './company';
import { PageFactory } from './page';
import { PersonFactory } from './person';
import { SettingsFactory } from './settings';
import { UploadFactory } from './uploads';
import { UserFactory } from './user';

export const createModels = (): IDbInterface => {
  const dialect = process.env.DB_DIALECT as 'mysql' | 'postgres' | 'sqlite' | 'mariadb' | 'mssql' | undefined;
  const port = Number(process.env.DB_PORT);
  const database = process.env.DB_NAME || '';
  const username = process.env.DB_USER || '';
  const logging = process.env.NODE_ENV === process.env.DB_LOG_ENV;
  const password = process.env.DB_PASS;
  const sequelize = new Sequelize(database, username, password, {
    define: {
      charset: 'utf8',
      timestamps: false,
    },
    dialect,
    logging,
    port,
  });

  const db: IDbInterface = {
    ArtTag: ArtTagFactory(sequelize),
    Article: ArticleFactory(sequelize),
    ArticleCategory: ArticleCategoryFactory(sequelize),
    ArticleTags: ArticleTagsFactory(sequelize),
    ArticleType: ArticleTypeFactory(sequelize),
    BriefCase: BriefCaseFactory(sequelize),
    CategoryTypes: CategoryTypesFactory(sequelize),
    Company: CompanyFactory(sequelize),
    InvestIdea: InvestIdeaFactory(sequelize),
    Page: PageFactory(sequelize),
    Person: PersonFactory(sequelize),
    Settings: SettingsFactory(sequelize),
    TechAnalysis: TechAnalysisFactory(sequelize),
    Upload: UploadFactory(sequelize),
    User: UserFactory(sequelize),
    sequelize,
  };

  Object.keys(db).forEach((modelName) => {
    const model = db[modelName];

    if (model.associate) {
      model.associate(db);
    }

    if (model.hooks) {
      model.hooks(db);
    }
  });

  return db;
};
